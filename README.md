# Comprehensive Cryptography Toolkit

A complete Python implementation of classical and modern cryptographic algorithms for educational and demonstration purposes.

## Features

### Classical Ciphers
- Caesar Cipher
- Monoalphabetic Cipher
- Playfair Cipher
- Vigenère Cipher
- Hill Cipher
- Rail Fence Cipher
- Columnar Transposition Cipher
- Vernam Cipher (One-Time Pad)

### Modern Symmetric Encryption
- DES (Data Encryption Standard)
- Triple DES (3DES)
- AES (Advanced Encryption Standard - 128, 192, 256-bit)
- Blowfish

### Modern Asymmetric Encryption
- RSA (Key generation, encryption, decryption)
- ElGamal Encryption
- ECC (Elliptic Curve Cryptography)

### Hash Functions
- MD5
- SHA-1
- SHA-256
- SHA-3 (Keccak)

### Digital Signatures
- RSA Digital Signature
- DSA (Digital Signature Algorithm)

### Key Exchange
- Diffie-Hellman Key Exchange

### Additional Features
- File encryption/decryption
- Text encryption/decryption
- Key management and storage
- Educational mode with step-by-step explanations
- Performance benchmarking
- Both console and GUI interfaces

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Console Interface
```bash
python main.py --console
```

### GUI Interface
```bash
python main.py --gui
```

### Educational Mode
```bash
python main.py --console --educational
```

## Project Structure

```
cryptography_project/
├── algorithms/
│   ├── classical/
│   ├── symmetric/
│   ├── asymmetric/
│   ├── hash/
│   └── signatures/
├── utils/
├── interface/
├── tests/
├── main.py
└── requirements.txt
```

## Educational Value

This toolkit is designed for:
- Learning cryptographic concepts
- Understanding algorithm implementations
- Comparing performance of different methods
- Demonstrating security principles

## License

MIT License - Educational use only
