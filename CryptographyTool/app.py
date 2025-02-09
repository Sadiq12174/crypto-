from flask import Flask, render_template, request, jsonify, send_from_directory
import hashlib
import os
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def derive_key(user_key):
    """Derives a 32-byte encryption key from the user input"""
    return base64.urlsafe_b64encode(hashlib.sha256(user_key.encode()).digest())

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    user_key = request.form.get("key")

    if not file or not user_key:
        return jsonify({"success": False, "message": "File or key missing"})

    derived_key = derive_key(user_key)
    cipher = Fernet(derived_key)

    data = file.read()
    encrypted_data = cipher.encrypt(data)

    filename = f"encrypted_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    return jsonify({"success": True, "filename": filename})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    user_key = request.form.get("key")

    if not file or not user_key:
        return jsonify({"success": False, "message": "File or key missing"})

    derived_key = derive_key(user_key)
    cipher = Fernet(derived_key)

    try:
        data = file.read()
        decrypted_data = cipher.decrypt(data)

        filename = f"decrypted_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        with open(filepath, "wb") as f:
            f.write(decrypted_data)

        return jsonify({"success": True, "filename": filename})
    except:
        return jsonify({"success": False, "message": "Wrong key entered"})

@app.route("/hash", methods=["POST"])
def hash_file():
    file = request.files.get("file")

    if not file:
        return jsonify({"success": False, "message": "File missing"})

    data = file.read()
    hash_code = hashlib.sha256(data).hexdigest()

    return jsonify({"success": True, "hash": hash_code})

@app.route("/encrypt-hash", methods=["POST"])
def encrypt_and_hash():
    file = request.files.get("file")
    user_key = request.form.get("key")

    if not file or not user_key:
        return jsonify({"success": False, "message": "File or key missing"})

    derived_key = derive_key(user_key)
    cipher = Fernet(derived_key)

    data = file.read()
    encrypted_data = cipher.encrypt(data)
    hash_code = hashlib.sha256(encrypted_data).hexdigest()

    return jsonify({"success": True, "hash": hash_code})

@app.route("/uploads/<filename>")
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
