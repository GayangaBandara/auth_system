from flask import Flask, request, render_template, redirect, url_for, flash, make_response
import sqlite3, hashlib, jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'simple_secret_key'
JWT_SECRET = 'simple_secret_key'

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

def create_token(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.username = data['username']
        except:
            flash('Invalid session. Please log in again')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required')
            return render_template('register.html')
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            token = create_token(username)
            resp = make_response(redirect(url_for('protected')))
            resp.set_cookie('token', token, httponly=True)
            flash('Login successful')
            return resp
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/protected')
@token_required
def protected():
    return render_template('protected.html', username=request.username)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    flash('You have been logged out.')
    return resp

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=3000)
