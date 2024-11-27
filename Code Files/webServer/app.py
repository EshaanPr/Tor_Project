'''
Eshaan Prakash(0303204p)
app.py

This script sets up a Flask web application with SQLAlchemy for database management and includes encryption functionality using the Fernet symmetric encryption method.

Functions:
    initialize_encryption_key() -> bytes:
        Checks if an encryption key already exists in the KeyStore table. If it does, returns the existing key. If not, generates a new key, stores it in the KeyStore table, and returns the new key.

Classes:
    KeyStore(db.Model):
        Represents the KeyStore table in the database, which stores encryption keys.
        Attributes:
            id (int): Primary key.
            key (str): The encryption key.

    Message(db.Model):
        Represents the Message table in the database, which stores messages.
        Attributes:
            id (int): Primary key.
            content (str): The message content.
            user_id (int): Foreign key referencing the User table.
            user (User): Relationship to the User model.

    User(db.Model):
        Represents the User table in the database, which stores user information.
        Attributes:
            id (int): Primary key.
            username (str): The username, which is unique.
            password_hash (str): The hashed password.

Main Execution:
    - Configures the Flask application and SQLAlchemy.
    - Defines the database models for KeyStore, Message, and User.
    - Implements the initialize_encryption_key function to manage encryption keys.

test user:
    username: test1
    password: testP

    username: test2
    password: testPP

    username: test3
    password: testPPP

You can delete the /instance/test.db file to reset the database.
'''

from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from flask_sqlalchemy import SQLAlchemy
import requests
import logging
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

class KeyStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(256), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

def initialize_encryption_key():
    # Check if key already exists
    existing_key = KeyStore.query.first()
    if existing_key:
        return existing_key.key
    
    # Generate and store new key if no existing key
    new_key = Fernet.generate_key()
    key_entry = KeyStore(key=new_key.decode())
    db.session.add(key_entry)
    db.session.commit()
    return new_key.decode()

with app.app_context():
    db.create_all()
    Message.__table__.create(db.engine, checkfirst=True)
    User.__table__.create(db.engine, checkfirst=True)
    KeyStore.__table__.create(db.engine, checkfirst=True)
    # Initialize the encryption key
    encryption_key = initialize_encryption_key()
    cipher_suite = Fernet(encryption_key.encode())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return "Username already exists"
        
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('messages'))
        return "Invalid username or password"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/messages')
def messages():
    decrypted_messages = []
    for msg in Message.query.all():
        try:
            decrypted_content = cipher_suite.decrypt(msg.content.encode()).decode()
            decrypted_messages.append((msg.id, decrypted_content, msg.user.username))
        except InvalidToken:
            logging.error(f"Invalid token. Decryption failed for message ID: {msg.id}")
            decrypted_messages.append((msg.id, "Decryption failed", msg.user.username))
    
    user_logged_in = 'user_id' in session
    username = session.get('username', 'Guest') if user_logged_in else 'Guest'
    
    return render_template('messages.html', messages=decrypted_messages, user_logged_in=user_logged_in, username=username)

@app.route('/post_message', methods=['POST'])
def post_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    if content:
        encrypted_content = cipher_suite.encrypt(content.encode()).decode()
        new_message = Message(content=encrypted_content, user_id=session['user_id'])
        db.session.add(new_message)
        db.session.commit()
    return redirect(url_for('messages'))

@app.route('/whois')
def whois():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logging.info(f"Client IP: {client_ip}")
    response = requests.get(f'https://ipwhois.app/json/{client_ip}')
    whois_info = response.json()

    # Check if WHOIS information is blank or incomplete
    if not whois_info or 'success' not in whois_info or not whois_info['success']:
        whois_info = {
            'ip': client_ip,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown'
        }

    return render_template('whois.html', whois_info=whois_info)

if __name__ == '__main__':
    app.run(debug=True)