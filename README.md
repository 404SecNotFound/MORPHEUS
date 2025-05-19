# Secure Data Encryption

Welcome to the **Secure Data Encryption** tool! This Python script allows you to securely encrypt and decrypt data using strong cryptographic practices.

## Features

- **Strong Encryption:** Utilizes AES-GCM for encryption, providing both confidentiality and integrity.
- **Secure Key Derivation:** Uses Scrypt KDF with a random salt to derive encryption keys from passwords.
- **Password Strength Enforcement:** Ensures that passwords meet complexity requirements for enhanced security.
- **Associated Authenticated Data (AAD):** Incorporates AAD to bind additional context to the ciphertext.
- **User-Friendly Interface:** Provides clear prompts and messages for easy interaction.
- **Stylish Interface:** Features an 80s-style ASCII art header and colorful outputs for an engaging user experience.

## Prerequisites

- Python 3.x installed on your system.
- Required Python packages:
  - `cryptography`
  - `colorama`
  - `pyfiglet`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/404securitynotfound/SecureDataEncryption.git
   cd SecureDataEncryption
   ```

2. **Install Dependencies**

It's recommended to use a virtual environment.

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt

```
## Usage
 - Run the script using Python:
```
python secure_data_encryption.py

```

## Encrypting Data

- The program will display a stylized header in bright green and prompt you to choose an action.
- Enter e to select encryption.
- Input the data you wish to encrypt.
- Provide a strong password that meets the complexity requirements:
- At least 12 characters long.
- Includes uppercase and lowercase letters.
- Contains digits and special characters.
- Confirm the password.
- The script will display the encrypted data in bright yellow text.

## Example

## Encryption

- Do you want to encrypt or decrypt? (e/d): e
- Enter the value to encrypt: MySecretData
- Enter the password:
- Confirm the password:

Encrypted data:
<encrypted data displayed in bright yellow>

## Decrypting Data

- Run the script and enter d to select decryption.
- Paste the base64-encoded encrypted data when prompted.
- Enter the password used during encryption.
- If the password is correct, the script will display the decrypted data.

## Decryption

- Do you want to encrypt or decrypt? (e/d): d
- Enter the encrypted data: <paste encrypted data>
- Enter the password:
- Decrypted data:
- MySecretData

## Notes

- Security Reminder: Always keep your passwords secure and do not share them.
- Dependencies: Ensure all dependencies are up to date to maintain security.
- Console Compatibility: For the best visual experience, use a console that supports ANSI escape codes and a monospaced font.

## License

- This project is licensed under the MIT License.

## Contributing

- Contributions are welcome! Please open an issue or submit a pull request for any improvements.

## Contact

- For any questions or feedback, please contact 404securitynotfound@protonmail.ch
