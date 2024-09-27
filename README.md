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
