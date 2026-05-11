"""Wrapper for Rabbit_Cipher.py to provide standard byte order and easy-to-use functions."""
from Rabbit_Cipher import Rabbit

def encrypt_bytes(key: bytes, data: bytes, iv: bytes = b"") -> bytes:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if iv and len(iv) != 8:
        raise ValueError("IV must be 8 bytes")

    # Reverse key and IV for internal representation of this specific implementation
    internal_key = key[::-1]
    internal_iv = iv[::-1] if iv else b""
    
    cipher = Rabbit(internal_key, internal_iv)
    
    # Generate keystream aligned to 16-byte blocks
    num_blocks = (len(data) + 15) // 16
    zeros = b"\x00" * (num_blocks * 16)
    raw_keystream = cipher.crypt(zeros)
    
    # Fix the keystream byte order (reverse each 16-byte block)
    fixed_keystream = bytearray()
    for i in range(0, len(raw_keystream), 16):
        fixed_keystream.extend(raw_keystream[i:i + 16][::-1])
        
    # XOR with actual data
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ fixed_keystream[i]
        
    return bytes(out)

def decrypt_bytes(key: bytes, data: bytes, iv: bytes = b"") -> bytes:
    return encrypt_bytes(key, data, iv)

def encrypt_hex(key_hex: str, data_hex: str, iv_hex: str = "") -> str:
    key = bytes.fromhex(key_hex)
    data = bytes.fromhex(data_hex)
    iv = bytes.fromhex(iv_hex) if iv_hex else b""
    return encrypt_bytes(key, data, iv).hex()

def decrypt_hex(key_hex: str, ct_hex: str, iv_hex: str = "") -> str:
    return encrypt_hex(key_hex, ct_hex, iv_hex)
