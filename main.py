#!/usr/bin/env python3
"""
Comprehensive Cryptography Toolkit - Main Entry Point

This is the main entry point for the cryptography toolkit.
It supports both console and GUI interfaces.
"""

import argparse
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from interface.console import ConsoleInterface


def main():
    """Main function to run the cryptography toolkit."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Cryptography Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --console                    # Run console interface
  python main.py --console --educational     # Run console interface with educational mode
  python main.py --gui                       # Run GUI interface (if available)
  python main.py --demo                      # Run demonstration mode
        """
    )
    
    parser.add_argument(
        '--console',
        action='store_true',
        help='Run console interface'
    )
    
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Run GUI interface (if available)'
    )
    
    parser.add_argument(
        '--educational',
        action='store_true',
        help='Enable educational mode (show intermediate steps)'
    )
    
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demonstration mode'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Comprehensive Cryptography Toolkit v1.0.0'
    )
    
    args = parser.parse_args()
    
    # If no interface specified, default to console
    if not any([args.console, args.gui, args.demo]):
        args.console = True
    
    try:
        if args.demo:
            run_demo_mode()
        elif args.console:
            run_console_interface(args.educational)
        elif args.gui:
            run_gui_interface(args.educational)
        else:
            print("No valid interface specified.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)


def run_console_interface(educational_mode=False):
    """Run the console interface."""
    print("Starting Console Interface...")
    interface = ConsoleInterface()
    if educational_mode:
        interface.educational_mode = True
        print("Educational mode enabled.")
    interface.run()


def run_gui_interface(educational_mode=False):
    """Run the GUI interface (placeholder for future implementation)."""
    print("GUI interface is not yet implemented.")
    print("Please use --console for the console interface.")
    print("Falling back to console interface...")
    run_console_interface(educational_mode)


def run_demo_mode():
    """Run demonstration mode showing various algorithms."""
    print("=== COMPREHENSIVE CRYPTOGRAPHY TOOLKIT - DEMO MODE ===\n")
    
    # Import algorithms for demonstration
    try:
        from algorithms.classical import CaesarCipher, VigenereCipher, PlayfairCipher
        from algorithms.hash import SHA256
        from algorithms.asymmetric import RSA
        
        print("1. Classical Ciphers Demo")
        print("-" * 30)
        
        # Caesar Cipher demo
        print("\nCaesar Cipher:")
        caesar = CaesarCipher(3)
        plaintext = "HELLO WORLD"
        encrypted = caesar.encrypt(plaintext)
        decrypted = caesar.decrypt(encrypted)
        print(f"  Plaintext: {plaintext}")
        print(f"  Encrypted: {encrypted}")
        print(f"  Decrypted: {decrypted}")
        
        # Vigenère Cipher demo
        print("\nVigenère Cipher:")
        vigenere = VigenereCipher("CRYPTO")
        encrypted = vigenere.encrypt(plaintext)
        decrypted = vigenere.decrypt(encrypted)
        print(f"  Plaintext: {plaintext}")
        print(f"  Encrypted: {encrypted}")
        print(f"  Decrypted: {decrypted}")
        
        # Playfair Cipher demo
        print("\nPlayfair Cipher:")
        playfair = PlayfairCipher("PLAYFAIR")
        encrypted = playfair.encrypt(plaintext)
        decrypted = playfair.decrypt(encrypted)
        print(f"  Plaintext: {plaintext}")
        print(f"  Encrypted: {encrypted}")
        print(f"  Decrypted: {decrypted}")
        
        print("\n2. Hash Functions Demo")
        print("-" * 30)
        
        # SHA-256 demo
        print("\nSHA-256:")
        sha256 = SHA256()
        hash_value = sha256.hash(plaintext)
        print(f"  Message: {plaintext}")
        print(f"  Hash: {hash_value}")
        
        print("\n3. Asymmetric Encryption Demo")
        print("-" * 30)
        
        # RSA demo
        print("\nRSA (512-bit keys for demo):")
        rsa = RSA(512)
        public_key, private_key = rsa.generate_keys()
        encrypted = rsa.encrypt("HI")
        decrypted = rsa.decrypt(encrypted)
        print(f"  Message: HI")
        print(f"  Encrypted: {encrypted}")
        print(f"  Decrypted: {decrypted}")
        
        print("\nDemo completed successfully!")
        print("\nTo explore more algorithms, run:")
        print("  python main.py --console")
        print("  python main.py --console --educational")
        
    except ImportError as e:
        print(f"Error importing algorithms: {e}")
        print("Please ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
    except Exception as e:
        print(f"Demo failed: {e}")


if __name__ == "__main__":
    main()
