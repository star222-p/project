from flask import Flask, render_template, request, send_file, redirect, url_for
from encryption import encrypt_file, decrypt_file, generate_file_hash
from Crypto.Random import get_random_bytes
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Upload and encrypt file
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            key = get_random_bytes(32)  # AES-256 key
            encrypted_file = encrypt_file(file_path, key)
            file_hash = generate_file_hash(file_path)
            return render_template('upload.html', encrypted_file=encrypted_file, key=key.hex(), file_hash=file_hash)
    return render_template('upload.html')

# Download and decrypt file
@app.route('/download', methods=['GET', 'POST'])
def download_file():
    if request.method == 'POST':
        enc_file_name = request.form['enc_file']
        key = request.form['key']
        if enc_file_name and key:
            dec_file = decrypt_file(os.path.join(UPLOAD_FOLDER, enc_file_name), bytes.fromhex(key))
            return send_file(dec_file, as_attachment=True)
    return render_template('download.html')

if __name__ == '__main__':
    app.run(debug=True)

