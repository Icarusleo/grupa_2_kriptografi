from hc256_wrapper import encrypt, decrypt


key_hex = "00" * 32      # 256-bit key = 32 bytes
nonce_hex = "00" * 32    # 256-bit IV/nonce = 32 bytes

plaintext_hex = "00" * 32  # 32 zero bytes

expected_ciphertext = (
    "5b078985d8f6f30d42c5c02fa6b67951"
    "53f06534801f89f24e74248b720b4818"
)

encrypted = encrypt(
    key=key_hex,
    nonce=nonce_hex,
    plaintext=plaintext_hex,
    key_encoding="hex",
    nonce_encoding="hex",
    plaintext_encoding="hex",
    output_encoding="hex",
)

print("ciphertext:", encrypted["ciphertext"])

assert encrypted["ciphertext"] == expected_ciphertext


decrypted = decrypt(
    key=key_hex,
    nonce=nonce_hex,
    ciphertext=encrypted["ciphertext"],
    key_encoding="hex",
    nonce_encoding="hex",
    ciphertext_encoding="hex",
    output_encoding="hex",
)

print("plaintext:", decrypted["plaintext"])

assert decrypted["plaintext"] == plaintext_hex

print("HC-256 test vector passed.")