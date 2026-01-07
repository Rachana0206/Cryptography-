#!/usr/bin/env python3
"""
Web Server for Comprehensive Cryptography Toolkit

This server provides:
1. Web interface for the toolkit
2. REST API endpoints for cryptographic operations
3. Real-time encryption/decryption capabilities
"""

from flask import Flask, render_template_string, request, jsonify, send_from_directory
import os
import sys
import json
from datetime import datetime

# Add current directory to path to find modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import cryptographic algorithms
try:
    from algorithms.classical import (
        CaesarCipher, VigenereCipher, PlayfairCipher, HillCipher,
        RailFenceCipher, MonoalphabeticCipher, ColumnarTranspositionCipher, VernamCipher
    )
    from algorithms.symmetric import AES, DES, TripleDES, Blowfish
    from algorithms.asymmetric import RSA, ElGamal, ECC
    from algorithms.hash import MD5, SHA1, SHA256, SHA3
    from algorithms.signatures import RSASignature, DSASignature
    from utils.file_utils import FileUtils
    from utils.performance import PerformanceBenchmark
    print("✓ All cryptographic modules imported successfully")
except ImportError as e:
    print(f"⚠️ Warning: Some modules could not be imported: {e}")

app = Flask(__name__)

# Global variables for storing keys and state
stored_keys = {}
performance_results = {}

@app.route('/')
def index():
    """Serve the main website."""
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return "Website file not found. Please ensure index.html exists."

@app.route('/<algorithm_name>')
def algorithm_page(algorithm_name):
    """Serve individual algorithm pages."""
    try:
        # Map algorithm IDs to actual filenames
        algorithm_files = {
            'caesar-cipher': 'caesar-cipher.html',
            'vigenere-cipher': 'vigenere-cipher.html',
            'playfair-cipher': 'playfair-cipher.html',
            'hill-cipher': 'hill-cipher.html',
            'rail-fence-cipher': 'rail-fence-cipher.html',
            'columnar-transposition': 'columnar-transposition-cipher.html',
            'vernam-cipher': 'vernam-cipher.html',
            'monoalphabetic': 'monoalphabetic-cipher.html',
            'aes': 'aes.html',
            'des': 'des.html',
            'triple-des': 'triple-des.html',
            'blowfish': 'blowfish.html',
            'rsa': 'rsa.html',
            'elgamal': 'elgamal.html',
            'ecc': 'ecc.html',
            # Hash and signatures
            'sha-256': 'sha256.html',
            'md5': 'md5.html',
            'sha-1': 'sha1.html',
            'sha-3': 'sha3.html',
            'rsa-signature': 'rsa-signature.html',
            'dsa': 'dsa.html',
            'diffie-hellman': 'diffie-hellman.html'
        }
        
        filename = algorithm_files.get(algorithm_name)
        if filename and os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                html_content = f.read()
            return html_content
        else:
            return f"Algorithm page '{algorithm_name}' not found. Please check the URL.", 404
            
    except FileNotFoundError:
        return f"Algorithm page '{algorithm_name}' not found.", 404
    except Exception as e:
        return f"Error loading algorithm page: {str(e)}", 500

@app.route('/api/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "toolkit": "Comprehensive Cryptography Toolkit",
        "version": "1.0.0"
    })

@app.route('/api/algorithms')
def get_algorithms():
    """Get list of available algorithms."""
    algorithms = {
        "classical": [
            {"name": "Caesar Cipher", "description": "Simple substitution cipher with shift-based encryption"},
            {"name": "Vigenère Cipher", "description": "Polyalphabetic substitution using keyword"},
            {"name": "Playfair Cipher", "description": "Digraphic substitution using 5x5 matrix"},
            {"name": "Hill Cipher", "description": "Matrix-based polygraphic substitution"},
            {"name": "Rail Fence Cipher", "description": "Transposition cipher with zigzag pattern"},
            {"name": "Columnar Transposition", "description": "Grid-based transposition using keyword"},
            {"name": "Vernam Cipher", "description": "One-time pad with perfect secrecy"},
            {"name": "Monoalphabetic", "description": "Random substitution mapping"}
        ],
        "symmetric": [
            {"name": "AES", "description": "Advanced Encryption Standard (128, 192, 256-bit)"},
            {"name": "DES", "description": "Data Encryption Standard (56-bit)"},
            {"name": "Triple DES", "description": "Enhanced security with triple encryption"},
            {"name": "Blowfish", "description": "Fast block cipher with variable key length"}
        ],
        "asymmetric": [
            {"name": "RSA", "description": "Public-key cryptography with key generation"},
            {"name": "ElGamal", "description": "Discrete logarithm-based encryption"},
            {"name": "ECC", "description": "Elliptic Curve Cryptography"}
        ],
        "hash": [
            {"name": "MD5", "description": "128-bit hash function (educational purposes)"},
            {"name": "SHA-1", "description": "160-bit secure hash algorithm"},
            {"name": "SHA-256", "description": "256-bit secure hash algorithm"},
            {"name": "SHA-3", "description": "Latest SHA family member (Keccak)"}
        ],
        "signatures": [
            {"name": "RSA Digital Signature", "description": "Digital signatures using RSA keys"},
            {"name": "DSA", "description": "Digital Signature Algorithm"}
        ]
    }
    return jsonify(algorithms)

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """Encrypt text using specified algorithm."""
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        plaintext = data.get('plaintext', '')
        key = data.get('key', '')
        educational_mode = data.get('educational_mode', False)
        
        if not algorithm or not plaintext:
            return jsonify({"error": "Algorithm and plaintext are required"}), 400
        
        result = perform_encryption(algorithm, plaintext, key, educational_mode)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """Decrypt text using specified algorithm."""
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        ciphertext = data.get('ciphertext', '')
        key = data.get('key', '')
        educational_mode = data.get('educational_mode', False)
        
        if not algorithm or not ciphertext:
            return jsonify({"error": "Algorithm and ciphertext are required"}), 400
        
        result = perform_decryption(algorithm, ciphertext, key, educational_mode)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/hash', methods=['POST'])
def hash_text():
    """Generate hash of text using specified algorithm."""
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        text = data.get('text', '')
        educational_mode = data.get('educational_mode', False)
        
        if not algorithm or not text:
            return jsonify({"error": "Algorithm and text are required"}), 400
        
        result = perform_hashing(algorithm, text, educational_mode)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """Generate cryptographic keys for specified algorithm."""
    try:
        data = request.get_json()
        algorithm = data.get('algorithm')
        key_size = data.get('key_size', 1024)
        
        if not algorithm:
            return jsonify({"error": "Algorithm is required"}), 400
        
        result = perform_key_generation(algorithm, key_size)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/performance', methods=['POST'])
def benchmark_performance():
    """Benchmark performance of algorithms."""
    try:
        data = request.get_json()
        algorithms = data.get('algorithms', [])
        data_size = data.get('data_size', 'medium')
        iterations = data.get('iterations', 100)
        
        if not algorithms:
            return jsonify({"error": "At least one algorithm is required"}), 400
        
        result = perform_benchmarking(algorithms, data_size, iterations)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def perform_encryption(algorithm, plaintext, key, educational_mode=False):
    """Perform encryption using specified algorithm."""
    try:
        if algorithm == "Caesar Cipher":
            shift = int(key) if key.isdigit() else 3
            cipher = CaesarCipher(shift)
            encrypted = cipher.encrypt(plaintext, educational_mode)
            return {
                "algorithm": algorithm,
                "plaintext": plaintext,
                "encrypted": encrypted,
                "key": str(shift),
                "educational_mode": educational_mode
            }
        
        elif algorithm == "Vigenère Cipher":
            keyword = key if key else "KEY"
            cipher = VigenereCipher(keyword)
            encrypted = cipher.encrypt(plaintext, educational_mode)
            return {
                "algorithm": algorithm,
                "plaintext": plaintext,
                "encrypted": encrypted,
                "key": keyword,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "Playfair Cipher":
            keyword = key if key else "PLAYFAIR"
            cipher = PlayfairCipher(keyword)
            encrypted = cipher.encrypt(plaintext, educational_mode)
            return {
                "algorithm": algorithm,
                "plaintext": plaintext,
                "encrypted": encrypted,
                "key": keyword,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "AES":
            password = key if key else "default_password"
            cipher = AES()
            encrypted = cipher.encrypt(plaintext, password, educational_mode)
            return {
                "algorithm": algorithm,
                "plaintext": plaintext,
                "encrypted": encrypted,
                "key": password,
                "educational_mode": educational_mode
            }
        
        else:
            return {"error": f"Algorithm {algorithm} not yet implemented for encryption"}
    
    except Exception as e:
        return {"error": f"Encryption failed: {str(e)}"}

def perform_decryption(algorithm, ciphertext, key, educational_mode=False):
    """Perform decryption using specified algorithm."""
    try:
        if algorithm == "Caesar Cipher":
            shift = int(key) if key.isdigit() else 3
            cipher = CaesarCipher(shift)
            decrypted = cipher.decrypt(ciphertext, educational_mode)
            return {
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "decrypted": decrypted,
                "key": str(shift),
                "educational_mode": educational_mode
            }
        
        elif algorithm == "Vigenère Cipher":
            keyword = key if key else "KEY"
            cipher = VigenereCipher(keyword)
            decrypted = cipher.decrypt(ciphertext, educational_mode)
            return {
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "decrypted": decrypted,
                "key": keyword,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "Playfair Cipher":
            keyword = key if key else "PLAYFAIR"
            cipher = PlayfairCipher(keyword)
            decrypted = cipher.decrypt(ciphertext, educational_mode)
            return {
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "decrypted": decrypted,
                "key": keyword,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "AES":
            password = key if key else "default_password"
            cipher = AES()
            decrypted = cipher.decrypt(ciphertext, password, educational_mode)
            return {
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "decrypted": decrypted,
                "key": password,
                "educational_mode": educational_mode
            }
        
        else:
            return {"error": f"Algorithm {algorithm} not yet implemented for decryption"}
    
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}

def perform_hashing(algorithm, text, educational_mode=False):
    """Perform hashing using specified algorithm."""
    try:
        if algorithm == "MD5":
            hasher = MD5()
            hash_value = hasher.hash(text)
            return {
                "algorithm": algorithm,
                "text": text,
                "hash": hash_value,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "SHA-1":
            hasher = SHA1()
            hash_value = hasher.hash(text)
            return {
                "algorithm": algorithm,
                "text": text,
                "hash": hash_value,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "SHA-256":
            hasher = SHA256()
            hash_value = hasher.hash(text, educational_mode)
            return {
                "algorithm": algorithm,
                "text": text,
                "hash": hash_value,
                "educational_mode": educational_mode
            }
        
        elif algorithm == "SHA-3":
            hasher = SHA3()
            hash_value = hasher.hash(text)
            return {
                "algorithm": algorithm,
                "text": text,
                "hash": hash_value,
                "educational_mode": educational_mode
            }
        
        else:
            return {"error": f"Hash algorithm {algorithm} not yet implemented"}
    
    except Exception as e:
        return {"error": f"Hashing failed: {str(e)}"}

def perform_key_generation(algorithm, key_size):
    """Generate keys for specified algorithm."""
    try:
        if algorithm == "RSA":
            rsa = RSA(key_size)
            public_key, private_key = rsa.generate_keys()
            return {
                "algorithm": algorithm,
                "key_size": key_size,
                "public_key": str(public_key),
                "private_key": str(private_key)
            }
        
        else:
            return {"error": f"Key generation for {algorithm} not yet implemented"}
    
    except Exception as e:
        return {"error": f"Key generation failed: {str(e)}"}

def perform_benchmarking(algorithms, data_size, iterations):
    """Benchmark performance of algorithms."""
    try:
        benchmark = PerformanceBenchmark()
        results = benchmark.run_benchmarks([data_size], iterations)
        
        # Filter results for requested algorithms
        filtered_results = {}
        for alg in algorithms:
            if alg in results:
                filtered_results[alg] = results[alg]
        
        return {
            "algorithms": algorithms,
            "data_size": data_size,
            "iterations": iterations,
            "results": filtered_results
        }
    
    except Exception as e:
        return {"error": f"Benchmarking failed: {str(e)}"}

@app.route('/api/demo')
def demo():
    """Run a quick demo of key algorithms."""
    try:
        # Caesar Cipher demo
        caesar = CaesarCipher(3)
        caesar_encrypted = caesar.encrypt("HELLO WORLD")
        caesar_decrypted = caesar.decrypt(caesar_encrypted)
        
        # Vigenère Cipher demo
        vigenere = VigenereCipher("CRYPTO")
        vigenere_encrypted = vigenere.encrypt("HELLO WORLD")
        vigenere_decrypted = vigenere.decrypt(vigenere_encrypted)
        
        # SHA-256 demo
        sha256 = SHA256()
        hash_value = sha256.hash("HELLO WORLD")
        
        demo_results = {
            "caesar_cipher": {
                "plaintext": "HELLO WORLD",
                "encrypted": caesar_encrypted,
                "decrypted": caesar_decrypted
            },
            "vigenere_cipher": {
                "plaintext": "HELLO WORLD",
                "encrypted": vigenere_encrypted,
                "decrypted": vigenere_decrypted
            },
            "sha256": {
                "text": "HELLO WORLD",
                "hash": hash_value
            }
        }
        
        return jsonify(demo_results)
    
    except Exception as e:
        return jsonify({"error": f"Demo failed: {str(e)}"}), 500

if __name__ == '__main__':
    print("🔐 Starting Comprehensive Cryptography Toolkit Web Server...")
    print("📱 Website available at: http://localhost:5000")
    print("🔌 API available at: http://localhost:5000/api")
    print("📊 Health check: http://localhost:5000/api/health")
    print("🎯 Demo: http://localhost:5000/api/demo")
    print("\nPress Ctrl+C to stop the server")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
