#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Display a message
echo "Setting up the Flask Password Manager project..."

# Create a virtual environment
echo "Creating a virtual environment..."
python -m venv venv

# Activate the virtual environment
echo "Activating the virtual environment..."
source venv/bin/activate

# Install the required packages
echo "Installing required packages..."
pip install Flask cryptography

# Create project directories and files if they don't exist
echo "Creating project structure..."
mkdir -p templates static/images

# Create example files (base.html, index.html, etc.)
echo "Creating example HTML templates..."
cat <<EOF > templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Manager</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
</head>
<body>
    <div class="container">
        <h1>Password Manager</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="flash {{ category }}">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
EOF

# Add more HTML template examples as needed

# Create the CSS file
echo "Creating CSS file..."
cat <<EOF > static/styles.css
/* Basic Reset */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

/* Body Styling */
body {
    font-family: Arial, sans-serif;
    background-color: #2c3e50;
    color: #ecf0f1;
    text-align: center;
}

/* Container Styling */
.container {
    max-width: 800px;
    margin: 20px auto;
    padding: 20px;
    background: rgba(0, 0, 0, 0.8);
    border-radius: 10px;
    box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
}

/* Header Styling */
h1 {
    font-size: 2.5em;
    margin-bottom: 20px;
    color: #e74c3c;
}

/* Navigation Menu */
.menu {
    display: flex;
    justify-content: center;
    margin-bottom: 20px;
}

.menu a {
    text-decoration: none;
    color: #ecf0f1;
    background-color: #e74c3c;
    padding: 10px 20px;
    border-radius: 5px;
    margin: 0 10px;
    font-weight: bold;
    transition: background-color 0.3s ease;
}

.menu a:hover {
    background-color: #c0392b;
}

/* Form Styling */
form {
    margin: 20px 0;
}

form label {
    display: block;
    margin: 10px 0 5px;
    font-size: 1.2em;
}

form input[type="text"],
form input[type="password"],
form input[type="number"] {
    width: 100%;
    padding: 10px;
    border: 1px solid #bdc3c7;
    border-radius: 5px;
    font-size: 1em;
}

form button {
    background-color: #27ae60;
    border: none;
    padding: 10px 20px;
    color: white;
    font-size: 1.2em;
    border-radius: 5px;
    cursor: pointer;
    margin-top: 10px;
    transition: background-color 0.3s ease;
}

form button:hover {
    background-color: #2ecc71;
}

/* Flash Messages */
.flash-messages {
    margin: 20px 0;
}

.flash {
    padding: 15px;
    border-radius: 5px;
    margin: 10px 0;
    font-size: 1.2em;
}

.flash.success {
    background-color: #2ecc71;
    color: #fff;
}

.flash.warning {
    background-color: #e67e22;
    color: #fff;
}

/* Background Image */
body {
    background-image: url('/static/images/hacker-background.jpg');
    background-size: cover;
    background-position: center;
}
EOF

# Create the app.py file
echo "Creating app.py file..."
cat <<EOF > app.py
from flask import Flask, render_template, request, redirect, url_for, flash
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import random
import string

app = Flask(__name__)
app.secret_key = 'supersecretkey'
KEY_FILE = 'key.key'
PASSWORD_FILE = 'passwords.json'

def generate_key(password):
    """Generate a key from a given password."""
    password = password.encode()
    salt = b'\\x00' * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def load_key():
    """Load the key from the key file or create it if it doesn't exist."""
    if not os.path.exists(KEY_FILE):
        password = request.form['password']
        key = generate_key(password)
        with open(KEY_FILE, 'wb') as file:
            file.write(key)
    with open(KEY_FILE, 'rb') as file:
        return file.read()

def encrypt_message(message, key):
    """Encrypt a message using the provided key."""
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    """Decrypt an encrypted message using the provided key."""
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

def save_password_data(data):
    """Save password data to a JSON file."""
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(data, file)

def load_password_data():
    """Load password data from a JSON file."""
    if not os.path.exists(PASSWORD_FILE):
        return {}
    with open(PASSWORD_FILE, 'r') as file:
        return json.load(file)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        service = request.form['service']
        password = request.form['password']
        key = load_key()
        encrypted_password = encrypt_message(password, key)
        data = load_password_data()
        data[service] = encrypted_password.decode()
        save_password_data(data)
        flash('Password added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_password.html')

@app.route('/retrieve_password', methods=['GET', 'POST'])
def retrieve_password():
    if request.method == 'POST':
        service = request.form['service']
        key = load_key()
        data = load_password_data()
        encrypted_password = data.get(service)
        if encrypted_password:
            decrypted_password = decrypt_message(encrypted_password.encode(), key)
            return render_template('retrieve_password.html', service=service, password=decrypted_password)
        else:
            flash('No password found for this service.', 'warning')
    return render_template('retrieve_password.html')

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if request.method == 'POST':
        service = request.form['service']
        new_password = request.form['new_password']
        key = load_key()
        data = load_password_data()
        if service in data:
            encrypted_password = encrypt_message(new_password, key)
            data[service] = encrypted_password.decode()
            save_password_data(data)
            flash('Password updated successfully!', 'success')
        else:
            flash('Service not found.', 'warning')
        return redirect(url_for('index'))
    return render_template('update_password.html')

@app.route('/delete_password', methods=['GET', 'POST'])
def delete_password():
    if request.method == 'POST':
        service = request.form['service']
        key = load_key()
        data = load_password_data()
        if service in data:
            del data[service]
            save_password_data(data)
            flash('Password deleted successfully!', 'success')
        else:
            flash('Service not found.', 'warning')
        return redirect(url_for('index'))
    return render_template('delete_password.html')

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if request.method == 'POST':
        length = int(request.form['length'])
        if length < 8:
            flash('Password length must be at least 8 characters.', 'warning')
        else:
            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(characters) for i in range(length))
            return render_template('generate_password.html', password=password)
    return render_template('generate_password.html')

if __name__ == '__main__':
    app.run(debug=True)

