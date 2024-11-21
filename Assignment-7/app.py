from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
import re
import time

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here_123!'  # Replace with a strong random key

users = {}

def validate_password(password):
    """Password complexity validator"""
    return (len(password) >= 8 and 
            re.search(r'[A-Z]', password) and 
            re.search(r'[a-z]', password) and 
            re.search(r'\d', password) and 
            re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username, password, confirm_password = request.form['username'], request.form['password'], request.form['confirm_password']

        if username in users:
            flash('Username exists', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif not validate_password(password):
            flash('Password requirements not met', 'error')
        else:
            users[username] = {'password': bcrypt.hashpw(password.encode(), bcrypt.gensalt()), 'failed_attempts': 0, 'locked_until': 0}
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        return render_template('signup.html')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        user = users.get(username)

        if not user:
            flash('Username not found', 'error')
        elif user['locked_until'] > int(time.time()):
            flash('Account locked. Try again later.', 'error')
        elif bcrypt.checkpw(password.encode(), user['password']):
            session['username'] = username
            user['failed_attempts'] = 0
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= 3:
                user['locked_until'] = int(time.time()) + 1800  # Lock for 30 minutes
                flash('Too many attempts. Account locked for 30 minutes.', 'error')
            else:
                flash(f'Invalid login. {3 - user["failed_attempts"]} attempts remaining.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Optional: Create a test user
    users['testuser'] = {'password': bcrypt.hashpw('TestPass123!'.encode(), bcrypt.gensalt()), 'failed_attempts': 0, 'locked_until': 0}
    app.run(debug=True)

