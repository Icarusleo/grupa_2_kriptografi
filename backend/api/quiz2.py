import ctypes

# 1. Load the library and define argument types
lib = ctypes.CDLL("C:/Users/HP/Desktop/VSCODE_FILES/kripto_quizler_github/grain.dll")

lib.crypto_aead_encrypt.restype = ctypes.c_int
lib.crypto_aead_encrypt.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),   # c
    ctypes.POINTER(ctypes.c_ulonglong), # clen
    ctypes.POINTER(ctypes.c_ubyte),   # m
    ctypes.c_ulonglong,               # mlen
    ctypes.POINTER(ctypes.c_ubyte),   # ad
    ctypes.c_ulonglong,               # adlen
    ctypes.POINTER(ctypes.c_ubyte),   # nsec (unused)
    ctypes.POINTER(ctypes.c_ubyte),   # npub (nonce)
    ctypes.POINTER(ctypes.c_ubyte),   # key
]




def fonksiyon(message = b"", associated_data = b"", key = bytes([0x00] * 16), nonce = bytes([0x00] * 12)):

    
    # 3. Convert Python bytes to C-compatible arrays
    m_buf = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    ad_buf = (ctypes.c_ubyte * len(associated_data)).from_buffer_copy(associated_data)
    key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
    nonce_buf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)

    # nsec is unused in Grain-128AEAD, so we pass a null pointer
    nsec_buf = ctypes.cast(None, ctypes.POINTER(ctypes.c_ubyte))

    # 4. Prepare the output buffers
    # The ciphertext length will be the message length + 8 bytes for the MAC/Tag
    max_c_len = len(message) + 8
    c_buf = (ctypes.c_ubyte * max_c_len)()
    clen = ctypes.c_ulonglong(0)

    # 5. Call the encryption function
    result = lib.crypto_aead_encrypt(
        c_buf, 
        ctypes.byref(clen),
        m_buf, len(message),
        ad_buf, len(associated_data),
        nsec_buf,
        nonce_buf,
        key_buf
    )
    if result == 0:
        print("Encryption successful!")
        # Extract exactly 'clen' bytes from the output buffer
        ciphertext = bytes(c_buf[:clen.value])
        print(f"Message length: {len(message)} bytes")
        print(f"Ciphertext length (including tag): {clen.value} bytes")
        print(f"Ciphertext (hex): {ciphertext.hex()}")

        ciphertext_hex = ciphertext.hex()

        ct = ciphertext_hex[:len(message)*2]
        tag = ciphertext_hex[len(message)*2:]

        return {
            "ciphertext": ct,
            "tag": tag
        }

    else:
        print(f"Encryption failed with error code: {result}")
        return None



# 2. Prepare the Python data
message = b""          # PT (boş)
associated_data = b""  # AD (boş)
key = bytes([0x00] * 16)   # 16 bytes of 0x00
nonce = bytes([0x00] * 12) # 12 bytes of 0x00

print(fonksiyon(message=message, associated_data=associated_data, key=key, nonce=nonce)) 