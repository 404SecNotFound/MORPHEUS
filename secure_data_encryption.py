import os
import sys
import base64
import getpass
import re
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from colorama import init, Fore, Style
import pyfiglet

init(autoreset=True)  # Initialize colorama

def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,  # 256 bits
        n=2**14,    # Adjusted CPU/memory cost factor
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def is_strong_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def parse_args():
    parser = argparse.ArgumentParser(description="Secure Data Encryption")
    parser.add_argument(
        "-o",
        "--operation",
        choices=["encrypt", "decrypt"],
        help="Operation to perform",
    )
    parser.add_argument(
        "-d",
        "--data",
        help="Plaintext for encryption or base64 ciphertext for decryption",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Password for encryption or decryption",
    )
    return parser.parse_args()

def encrypt(plaintext, password):
    salt = os.urandom(16)   # 128-bit salt
    nonce = os.urandom(12)  # 96-bit nonce
    aad = b"SecureData"     # Associated Authenticated Data

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)

    encrypted_data = salt + nonce + ciphertext
    b64_encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')

    # Clear sensitive data from memory
    key = None
    password = None
    plaintext = None

    return b64_encrypted_data

def decrypt(b64_encrypted_data, password):
    try:
        encrypted_data = base64.b64decode(b64_encrypted_data)
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        aad = b"SecureData"  # Associated Authenticated Data

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        # Clear sensitive data from memory
        key = None
        password = None

        return plaintext.decode('utf-8')
    except InvalidTag:
        print("\nDecryption failed: Incorrect password or corrupted data.")
        return None
    except Exception as e:
        print(f"\nAn error occurred during decryption: {e}")
        return None

def main():
    args = parse_args()
    # Create an ASCII art header with the new text
    ascii_banner = pyfiglet.figlet_format("404SecurityNotFound")
    print(Fore.GREEN + Style.BRIGHT + ascii_banner)

    if args.operation:
        action = args.operation[0].lower()
    else:
        action = input("Do you want to encrypt or decrypt? (e/d): ").strip().lower()

    if action == 'e':
        if args.data:
            plaintext = args.data
        else:
            plaintext = input("Enter the value to encrypt: ").strip()
        if args.password:
            password = args.password
            password_confirm = args.password
        else:
            password = getpass.getpass("Enter the password: ")
            password_confirm = getpass.getpass("Confirm the password: ")
        
        if password != password_confirm:
            print("Passwords do not match.")
            sys.exit(1)
        
        if not password:
            print("Password cannot be empty.")
            sys.exit(1)
        
        if not is_strong_password(password):
            print("Password is not strong enough. It must be at least 12 characters long, contain uppercase and lowercase letters, digits, and special characters.")
            sys.exit(1)

        encrypted = encrypt(plaintext, password)
        print("\nEncrypted data:")
        print(Fore.YELLOW + Style.BRIGHT + encrypted)

        # Clear sensitive data from memory
        password = None
        password_confirm = None
        plaintext = None
        
    elif action == 'd':
        if args.data:
            b64_encrypted_data = args.data
        else:
            b64_encrypted_data = input("Enter the encrypted data: ").strip()
        if args.password:
            password = args.password
        else:
            password = getpass.getpass("Enter the password: ")
        
        if not password:
            print("Password cannot be empty.")
            sys.exit(1)

        decrypted = decrypt(b64_encrypted_data, password)
        if decrypted is not None:
            print("\nDecrypted data:")
            print(decrypted)

        # Clear sensitive data from memory
        password = None
        b64_encrypted_data = None
    else:
        print("Invalid option.")
        sys.exit(1)

if __name__ == '__main__':
    main()
