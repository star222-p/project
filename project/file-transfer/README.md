# Secure File Transfer Application

A web-based secure file transfer application that allows users to encrypt files before uploading and securely decrypt files after downloading. The application ensures confidentiality and integrity of the transferred files using AES encryption and SHA-256 hashing.

## Features
- **Upload & Encrypt**: Upload files securely and encrypt them using AES-256 encryption.
- **Download & Decrypt**: Download encrypted files and decrypt them using the correct key.
- **Hash Verification**: The application generates an SHA-256 hash for the uploaded files to verify their integrity.

## Tech Stack
- **Frontend**: HTML, CSS
- **Backend**: Python (Flask)
- **Encryption**: AES (PyCryptodome)
- **Hashing**: SHA-256 (hashlib)

## Project Structure

/secure_file_transfer /static - style.css /templates - index.html - upload.html - download.html app.py encryption.py README.md


## Prerequisites

- Python 3.7+
- `pip` (Python package installer)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/secure-file-transfer.git
    cd secure-file-transfer
    ```

2. Install the required Python packages:
    ```bash
    pip install flask pycryptodome
    ```

3. Run the application:
    ```bash
    python app.py
    ```

4. Open your web browser and navigate to:
    ```
    http://127.0.0.1:5000/
    ```

## How to Use

### 1. **Upload & Encrypt a File**

- Navigate to the **Upload & Encrypt File** section.
- Select a file and click **Upload & Encrypt**.
- The application will encrypt the file using AES-256 and display the encryption key (in hexadecimal format) and the SHA-256 file hash.
  - **Save the encryption key** to decrypt the file later.
  
### 2. **Download & Decrypt a File**

- Navigate to the **Download & Decrypt File** section.
- Enter the name of the encrypted file and provide the encryption key.
- The application will decrypt the file and provide it for download.

## Key Information

- **AES-256 Encryption**: This application uses the AES-256 encryption algorithm with GCM (Galois/Counter Mode), which provides both confidentiality and data integrity.
- **SHA-256 Hashing**: After uploading a file, the app generates an SHA-256 hash for integrity verification.

## Screenshots

- **Home Page**

  ![Home Page](./screenshots/homepage.png)

- **Upload & Encrypt Page**

  ![Upload & Encrypt](./screenshots/upload_encrypt.png)

- **Download & Decrypt Page**

  ![Download & Decrypt](./screenshots/download_decrypt.png)

## Security Considerations

- The encryption key generated for each file is unique and **must be stored securely**. Without the key, files cannot be decrypted.
- All files are processed on the server-side, ensuring secure handling during encryption and decryption.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- **Your Name** - [GitHub Profile](https://github.com/yourusername)

