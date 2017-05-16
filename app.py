#!/env/bin/python
from flask import Flask, session, escape, render_template, request, url_for, redirect
from lib.auth import Auth

auth = Auth()
app = application = Flask(__name__)

#add the secret key from the config 
#to allow Flask sessions to work
app.secret_key = auth.config['app']['secret_key']

@app.route('/')
def index():
    logged_in = session.get('logged_in')
    if logged_in:
        return 'logged in!'
    else:
        return 'not logged in. <a href="/login">Click here</a> to login.'

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        password = request.form.get('password')
        email = request.form.get('email')
        response = auth.login(email, password)
        if response['success']:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', message = response['response_text'])

@app.route('/createaccount', methods = ['GET', 'POST'])
def createaccount():
    if request.method == 'GET':
        return render_template('createaccount.html')
    if request.method == 'POST':
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        response = auth.create_user(email = email, password1 = password1, password2 = password2)
        return render_template('createaccount.html', message = response['response_text'])

@app.route('/verify')
def verify():
    email = request.args.get('email')
    verification_token = request.args.get('token')
    if not email or not verification_token:
        return 'No email or token'

    auth = Auth()
    response = auth.verify(email = email, verification_token = verification_token)
    return response['response_text']

def main():
    app.run(debug = True, port = auth.config['server']['port'])

if __name__ == '__main__':
    main()

