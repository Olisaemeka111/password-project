from flask import Flask, request, render_template, jsonify
import os
import base64
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone

app = Flask(__name__, template_folder=os.path.abspath("templates"))

# Constants
SALT_FILE = "salt.txt"
PASSWORDS_FILE = "passwords.enc"
SALT_SIZE = 16
ITERATIONS = 100000
PASSWORD_EXPIRY_DAYS = 0.06942

# Function to generate a key from the master password and salt
def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# Function to save the salt to a file
def save_salt(salt):
    with open(SALT_FILE, 'wb') as file:
        file.write(salt)

# Function to load the salt from the file
def load_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as file:
            return file.read()
    else:
        salt = os.urandom(SALT_SIZE)
        save_salt(salt)
        return salt

# Function to add a password for a service
def add_password(service, master_password):
    salt = load_salt()
    key = generate_key(master_password, salt)
    fernet = Fernet(key)

    passwords = {}
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'rb') as file:
            encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                passwords = json.loads(decrypted_data.decode())
            except InvalidToken:
                return "Invalid master password."
            except json.JSONDecodeError as e:
                return f"Error decoding JSON: {e}"

    passwords[service] = {
        "password": base64.urlsafe_b64encode(os.urandom(16)).decode(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    encrypted_data = fernet.encrypt(json.dumps(passwords).encode())

    with open(PASSWORDS_FILE, 'wb') as file:
        file.write(encrypted_data)

    return f"Password for {service} added."

# Function to retrieve a password for a service
def get_password(service, master_password):
    salt = load_salt()
    key = generate_key(master_password, salt)
    fernet = Fernet(key)

    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'rb') as file:
            encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                passwords = json.loads(decrypted_data.decode())

                if service in passwords:
                    data = passwords[service]
                    if isinstance(data, dict) and "timestamp" in data:
                        timestamp = datetime.fromisoformat(data["timestamp"])
                        if datetime.now(timezone.utc) - timestamp > timedelta(days=PASSWORD_EXPIRY_DAYS):
                            new_password = base64.urlsafe_b64encode(os.urandom(16)).decode()
                            passwords[service] = {
                                "password": new_password,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                            encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
                            with open(PASSWORDS_FILE, 'wb') as file:
                                file.write(encrypted_data)
                            return new_password
                        else:
                            return data["password"]
                    else:
                        print(f"Warning: Legacy data found for {service}.")
                        new_password = base64.urlsafe_b64encode(os.urandom(16)).decode()
                        passwords[service] = {
                            "password": new_password,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
                        with open(PASSWORDS_FILE, 'wb') as file:
                            file.write(encrypted_data)
                        return new_password
                else:
                    return "Service not found."

            except InvalidToken:
                return "Invalid master password."
            except json.JSONDecodeError as e:
                return f"Error decoding JSON: {e}"
    else:
        return "No passwords stored."

# Route to list all stored passwords
@app.route('/list_passwords', methods=['POST'])
def list_passwords():
    master_password = request.json.get('master_password')

    if not master_password:
        return jsonify({"error": "Master password is required."}), 400

    salt = load_salt()
    key = generate_key(master_password, salt)
    fernet = Fernet(key)

    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'rb') as file:
            encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                passwords = json.loads(decrypted_data.decode())

                response = {}
                for service, data in passwords.items():
                    if isinstance(data, dict) and "password" in data:
                        timestamp = datetime.fromisoformat(data.get("timestamp", "1970-01-01T00:00:00+00:00"))
                        if datetime.now(timezone.utc) - timestamp > timedelta(days=PASSWORD_EXPIRY_DAYS):
                            new_password = base64.urlsafe_b64encode(os.urandom(16)).decode()
                            passwords[service] = {
                                "password": new_password,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                        response[service] = passwords[service]["password"]
                    else:
                        response[service] = "Corrupted data format."

                encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
                with open(PASSWORDS_FILE, 'wb') as file:
                    file.write(encrypted_data)

                return jsonify(response)

            except InvalidToken:
                return jsonify({"error": "Invalid master password."}), 401
            except json.JSONDecodeError as e:
                return jsonify({"error": f"Error decoding JSON: {e}"}), 500
            except Exception as e:
                return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "No passwords stored."}), 404

# Routes
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/add_password', methods=['POST'])
def add_new_password():
    service = request.form.get('service')
    master_password = request.form.get('master_password')
    result = add_password(service, master_password)
    return {"status": result}

@app.route('/get_password', methods=['POST'])
def get_password_route():
    service = request.form.get('service')
    master_password = request.form.get('master_password')
    password = get_password(service, master_password)
    return {"password": password}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)