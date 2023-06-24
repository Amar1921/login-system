import bcrypt
from email_validator import validate_email, EmailNotValidError
from flask import Flask, request, render_template, session, redirect
from mysql import connector

app = Flask(__name__)
app.secret_key = "As78-@Lx^-kpe9!y"
users_connected = []


# Initialisation de la base de donnees
class Connexion:
    db = connector.connect(
        user='root',
        password='root',
        database='users',
        host='127.0.0.1',
        port=8889
    )

    def getUser(self, email):
        ma_bd = self.db.cursor()
        req = "SELECT * FROM user WHERE email=%s"
        ma_bd.execute(req, [email])
        return ma_bd.fetchall()

    def addUser(self, email, password):
        ma_bd = self.db.cursor()
        req = "INSERT INTO user(email, password) VALUES (%s, %s)"
        params = (email, password)
        ma_bd.execute(req, params)
        self.db.commit()
        ma_bd.close()


# Initialisation de la class Connect
connexion = Connexion()


# Route vers la page d'accueil
@app.route('/', methods=['GET'])
def home():
    if 'user' in session:
        user = session['user']
        users_connected.append(user)
        if 'anonyme' in users_connected:
            users_connected.remove('anonyme')
        return render_template('base.html', user=user, deconnecter=True,
                               users=users_connected)

    return render_template('base.html')


# Route vers la page login
@app.route('/login', methods=['POST', 'GET'])
def login():
    # Si deja une session
    if 'user' in session:
        # email = session['user']
        return render_template('base.html', user=session['user'])
    elif request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        try:

            email = request.form['email']
            password = request.form['password']
            password = password.encode('utf-8')
            # Verifier si le compte existe deja
            # ma_bdd = connexion.db.cursor(prepared=True)
            # req = "SELECT * FROM user WHERE email=%s"
            # ma_bdd.execute(req, [email])
            # result = ma_bdd.fetchall()
            # ma_bdd.close()
            # connexion.db.commit()
            # connexion.db.close()
            result = connexion.getUser(email)
            email2 = ""
            passwordHash = ""
            # Si le compte existe !
            if result is not None:
                for res in result:
                    email2 = res[1]
                    passwordHash = res[2].encode('utf-8')
                print(email2)
                # Si l'utilisateur existe et que le mot de passe est correcte
                if email2 is not None and bcrypt.checkpw(password, passwordHash):
                    print("Les mots de passe correspondent")
                    session['user'] = email
                    # users_connected.append(email)
                    return render_template('login.html',
                                           login=True,
                                           user=email)
                else:
                    message = "Mot de passe incorrecte"
                    return render_template('login.html',
                                           error=message)
        except:
            message = "Cet utilisateur n'existe pas"
            print("Cet utilisation n'existe pas")

            return render_template('login.html',
                                   error=message)
    else:
        return render_template('login.html')


# Route vers la page d'inscription
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    # Effacer la session en cours.
    session.clear()
    if request.method == 'POST':
        email = request.form['email']
        try:
            # Verifier si le format de l'email est valide
            email = validate_email(email).email
            resultat = connexion.getUser(email)

            # Si resultat est vrai
            if resultat:
                print("***********2***************")
                erreur = "Ce utilisateur existe deja !!"
                return render_template('signup.html',
                                       message=erreur)
            else:
                # Si l'email est valide et que l'utilisateur n'existe pas encore
                password = request.form['password']
                passwordCf = request.form['passwordCf']
                # Verifier si les mots de passe sont conformes et != null
                if password == passwordCf and password != "":

                    password = password.encode('utf-8')
                    # Crypter le mot de passe
                    hased = bcrypt.hashpw(password, bcrypt.gensalt())
                    connexion.addUser(email, hased)
                    return render_template('login.html',
                                           title="login")
                else:
                    error = "Mot de passe incorrecte"
                    return render_template('signup.html',
                                           title="login",
                                           message=error)
        except EmailNotValidError as e:
            print(str(e))
            e = "Email non valide"
            return render_template('signup.html',
                                   title="login",
                                   message=e)
    return render_template('signup.html',
                           title="login")


# Route pour la déconnexion
@app.route('/logout')
def logout():
    # Supprimer le nom d'utilisateur de la session
    session.pop('user', None)
    session.clear()
    users_connected.clear()
    return redirect('/')


# Route pour la page d'erreur
@app.errorhandler(404)
def route404(erreur):
    return render_template(
        '404.html',
        code=404,
        error=erreur,
        message="La page que vous avez demandé n\'est pas disponible.")
