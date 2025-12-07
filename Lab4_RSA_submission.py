"""
Lab Assignment 4 - Information Security (Python Implementation)
Includes:
- Task 1: Simple RSA Implementation (without external libraries) using small primes
- Task 2: RSA using PyCryptodome (if available). If not installed, instructions are printed.
- Task 3: Create and verify a digital signature (uses PyCryptodome if available, else a manual method)

Author: Generated for student submission
Comments: This file includes explanatory comments. Run with Python 3.8+.
"""

# Standard library imports
import math
import random
import hashlib
import binascii

# ------------------------
# Task 1: Simple RSA (manual)
# ------------------------

def egcd(a, b):
    # Extended Euclidean Algorithm to find modular inverse
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    # Return modular inverse of a mod m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def simple_rsa_keygen(p, q, e=7):
    # Key generation using small primes p and q
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime")
    d = modinv(e, phi)
    return (e, d, n)

def rsa_encrypt(m_int, e, n):
    # Encrypt integer message m_int using public key (e, n)
    return pow(m_int, e, n)

def rsa_decrypt(c_int, d, n):
    # Decrypt integer ciphertext c_int using private key (d, n)
    return pow(c_int, d, n)

# Helper: convert text to integer and back (naive)
def text_to_int(msg):
    # Convert bytes to integer
    return int.from_bytes(msg.encode('utf-8'), byteorder='big')

def int_to_text(m_int):
    # Convert integer back to text (may raise if leading zeros lost)
    length = (m_int.bit_length() + 7) // 8
    return m_int.to_bytes(length, byteorder='big').decode('utf-8', errors='ignore')

# Example usage for Task 1
def task1_demo(name_str="S"):
    # Demo showing encryption/decryption of a short string (single character recommended for small n)
    # Choose small primes
    p = 11
    q = 13
    e_default = 7
    e, d, n = None, None, None
    e, d, n = simple_rsa_keygen(p, q, e_default)[0], simple_rsa_keygen(p, q, e_default)[1], simple_rsa_keygen(p, q, e_default)[2]
    # For brevity we only encrypt one character (fits in small n)
    m_int = text_to_int(name_str)
    c_int = rsa_encrypt(m_int, e, n)
    m2_int = rsa_decrypt(c_int, d, n)
    m2 = int_to_text(m2_int)
    return {
        "p": p, "q": q, "n": n, "e": e, "d": d,
        "message": name_str, "m_int": m_int, "cipher": c_int, "decrypted_int": m2_int, "decrypted": m2
    }

# ------------------------
# Task 2: RSA with PyCryptodome (concept + code if available)
# ------------------------

pycryptodome_available = False
try:
    from Crypto.PublicKey import RSA as RSA_crypto
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256 as SHA256_crypto
    pycryptodome_available = True
except Exception as ex:
    pycryptodome_available = False

def task2_generate_keys_pycryptodome():
    # Generate 2048-bit RSA key pair using PyCryptodome (if available)
    if not pycryptodome_available:
        raise ImportError("PyCryptodome not available. Install with: pip install pycryptodome")
    key = RSA_crypto.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key, key

def task2_encrypt_decrypt(message):
    # If PyCryptodome available, perform encryption/decryption and return hex displays
    if not pycryptodome_available:
        return {"error": "PyCryptodome not installed"}
    priv_bytes, pub_bytes, key_obj = task2_generate_keys_pycryptodome()
    pub = RSA_crypto.import_key(pub_bytes)
    priv = RSA_crypto.import_key(priv_bytes)
    cipher = PKCS1_OAEP.new(pub)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    # Decrypt
    cipher_dec = PKCS1_OAEP.new(priv)
    plaintext = cipher_dec.decrypt(ciphertext).decode('utf-8', errors='ignore')
    return {
        "public_key_pem": pub_bytes.decode('utf-8'),
        "private_key_pem": priv_bytes.decode('utf-8'),
        "cipher_hex": binascii.hexlify(ciphertext).decode('utf-8'),
        "plaintext": plaintext
    }

# ------------------------
# Task 3: Digital Signature (try PyCryptodome, else manual)
# ------------------------

def manual_sign_verify(message, d, n, e):
    # Manual signature: sign by pow(hash_int, d, n) and verify by pow(sig, e, n) == hash_int
    h = hashlib.sha256(message.encode('utf-8')).digest()
    h_int = int.from_bytes(h, byteorder='big')
    signature = pow(h_int, d, n)
    # verify
    recovered = pow(signature, e, n)
    valid = (recovered == h_int % n)
    return {
        "hash_hex": h.hex(),
        "hash_int": h_int,
        "signature_int": signature,
        "verified": valid
    }

def task3_demo(message="Information Security Lab 4"):
    # Generate keys via PyCryptodome if available and perform signing & verification. If not available, show manual method using small keys.
    if pycryptodome_available:
        key = RSA_crypto.generate(2048)
        priv = key
        pub = key.publickey()
        h = SHA256_crypto.new(message.encode('utf-8'))
        signature = pkcs1_15.new(priv).sign(h)
        # verify
        try:
            pkcs1_15.new(pub).verify(h, signature)
            verified = True
        except (ValueError, TypeError):
            verified = False
        return {
            "method": "pycryptodome",
            "public_pem": pub.export_key().decode('utf-8'),
            "private_pem": priv.export_key().decode('utf-8'),
            "message": message,
            "hash_hex": h.hexdigest(),
            "signature_hex": binascii.hexlify(signature).decode('utf-8'),
            "verified": verified
        }
    else:
        # fallback demonstration using small primes (NOT SECURE) for educational purposes
        p = 101
        q = 113
        e_default = 65537
        # compute n, phi
        n = p * q
        phi = (p - 1) * (q - 1)
        # pick small e that is coprime: use 17 if possible
        e = 17 if math.gcd(17, phi) == 1 else 3
        d = modinv(e, phi)
        result = manual_sign_verify(message, d, n, e)
        result.update({"n": n, "e": e, "d": d, "method": "manual_fallback"})
        return result

# ------------------------
# If run as script, write outputs for demonstration
# ------------------------
if __name__ == "__main__":
    print("=== Task 1 Demo (Simple RSA) ===")
    res1 = task1_demo("S")
    for k, v in res1.items():
        print(f"{k}: {v}")
    print("\n=== Task 2 Demo (PyCryptodome) ===")
    if pycryptodome_available:
        res2 = task2_encrypt_decrypt("Hello from Lab 4")
        print("Cipher (hex):", res2["cipher_hex"])
        print("Decrypted:", res2["plaintext"])
    else:
        print("PyCryptodome not installed. Install with: pip install pycryptodome")
    print("\n=== Task 3 Demo (Digital Signature) ===")
    res3 = task3_demo("Information Security Lab 4")
    # print selective fields
    if res3.get("method") == "pycryptodome":
        print("Signature (hex):", res3["signature_hex"])
        print("Verified:", res3["verified"])
    else:
        print("Manual fallback signature int:", res3.get("signature_int"))
        print("Verified:", res3.get("verified"))
