import bcrypt
from email_validator import validate_email, EmailNotValidError
from flask import Flask, request, render_template, session, redirect
from mysql import connector

app = Flask(__name__)
app.secret_key = "As78-@Lx^-kpe9!y"

# Initialisation de la base de donnees
db = connector.connect(
    user='root',
    password='root',
    database='users',
    host='127.0.0.1',
    port=8889
)


@app.route('/')
def home():
    if 'user' in session:
        email = session['user']
        return render_template('base.html', user=email)
    else:
        return render_template('login.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    # Si deja une session
    if 'user' in session:
        # email = session['user']
        return redirect('/')

    elif request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        try:

            email = request.form['email']
            password = request.form['password']
            password = password.encode('utf-8')
            # Verifier si le compte existe deja
            ma_bdd = db.cursor(prepared=True)
            req = "SELECT * FROM user WHERE email=%s"
            ma_bdd.execute(req, [email])
            result = ma_bdd.fetchall()
            ma_bdd.close()

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
                    return render_template('base.html')
                else:
                    message = "Mot de passe incorrecte"
                    return render_template('login.html',
                                           error=message)
        except:
            message = "Cet utilisateur n'existe pas"
            print("Cet utilisation n'existe pas")

            return render_template('login.html',
                                   error=message)

    return render_template('login.html')


#
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    # Effacer la session en cours.
    session.clear()
    if request.method == 'POST':
        email = request.form['email']
        try:
            # Verifier si le format de l'email est valide
            email = validate_email(email).email

            ma_bdd = db.cursor(prepared=True)
            req = "SELECT * FROM user WHERE email=%s"
            ma_bdd.execute(req, [email])
            resultat = ma_bdd.fetchall()
            ma_bdd.close()
            # Si resultat est True
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
                    ma_bdd = db.cursor(prepared=True)
                    password = password.encode('utf-8')
                    # Crypter le mot de passe
                    hased = bcrypt.hashpw(password, bcrypt.gensalt())

                    req = "INSERT INTO user (email, password) VALUES (%s, %s);"
                    # req = req.format(email, hased)
                    params = [(email, hased)]
                    ma_bdd.executemany(req, params)
                    # print(res)
                    db.commit()
                    ma_bdd.close()
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
    return redirect('/')


# Route pour la page d'erreur
@app.errorhandler(404)
def route404(erreur):
    return render_template(
        '404.html',
        code=404,
        error=erreur,
        message="La page que vous avez demandé n\'est pas disponible.")
