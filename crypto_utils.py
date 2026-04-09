# crypto_utils.py
# ============================================================
# AES-256-CBC Encryption / Decryption  (Security Mechanism)
# ============================================================

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Shared secret key — In production, use proper key exchange (e.g., DH/RSA)
SHARED_SECRET = b"RFTP_SECRET_KEY_CHANGE_IN_PROD!!"   # 32 bytes -> AES-256


def derive_key(secret: bytes) -> bytes:
    """Derive a 32-byte key via SHA-256."""
    return hashlib.sha256(secret).digest()


def encrypt(plaintext: bytes, secret: bytes = SHARED_SECRET) -> bytes:
    """
    AES-256-CBC encrypt.
    Returns: IV (16 bytes) + ciphertext
    """
    key = derive_key(secret)
    iv  = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ct


def decrypt(ciphertext: bytes, secret: bytes = SHARED_SECRET) -> bytes:
    """
    AES-256-CBC decrypt.
    Expects: IV (16 bytes) + ciphertext
    """
    key = derive_key(secret)
    iv  = ciphertext[:16]
    ct  = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def encrypt_packet(raw_packet: bytes) -> bytes:
    """Encrypt an entire RFTP packet payload region (after header)."""
    return encrypt(raw_packet)


def decrypt_packet(encrypted: bytes) -> bytes:
    """Decrypt an entire RFTP packet payload region."""
    return decrypt(encrypted)