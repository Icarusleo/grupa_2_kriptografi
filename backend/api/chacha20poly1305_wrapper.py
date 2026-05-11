from chacha20poly1305 import ChaCha20Poly1305, TagInvalidException


# ============================================================
# Frontend Developer Usage Manual
# ============================================================
#
# This wrapper expects key, nonce, and AAD from the frontend as BIT STRINGS.
#
# Required input sizes:
#   key   -> exactly 256 bits
#   nonce -> exactly 96 bits
#   aad   -> any length, but length must be a multiple of 8 bits
#
# Example bit string:
#   "0100000101000010"  means bytes b"AB"
#
# Encryption returns:
#   {
#       "ciphertext": "...",
#       "tag": "...",
#       "output": "..."
#   }
#
# output = ciphertext || tag
#
# For decryption, frontend can send either:
#   1. ciphertext and tag separately
#   2. ciphertext already combined as ciphertext || tag, with tag=None
#
# No padding is applied in this wrapper.
# Key and nonce must already have correct length.
#
# ============================================================


KEY_SIZE = 32      # 256 bits
NONCE_SIZE = 12    # 96 bits
TAG_SIZE = 16      # 128 bits


def _bits_to_bytes(bit_string, name="value"):
    """
    Convert a bit string like '01010101' to bytes.

    Spaces and underscores are allowed for readability:
        '0101 0101'
        '0101_0101'
    """
    if not isinstance(bit_string, str):
        raise TypeError(f"{name} must be a bit string")

    bit_string = bit_string.replace(" ", "").replace("_", "")

    if bit_string == "":
        return b""

    if any(ch not in "01" for ch in bit_string):
        raise ValueError(f"{name} must contain only 0 and 1")

    if len(bit_string) % 8 != 0:
        raise ValueError(f"{name} bit length must be a multiple of 8")

    return int(bit_string, 2).to_bytes(len(bit_string) // 8, byteorder="big")


def _hex_to_bits(hex_string):
    """
    Helper used only for test vectors.
    Converts hex string to bit string.
    """
    raw = bytes.fromhex(hex_string)
    return "".join(f"{byte:08b}" for byte in raw)


def _to_bytes(value, encoding="raw", name="value"):
    """
    Convert input to bytes.

    Supported encodings:
        "bits" -> bit string to bytes
        "hex"  -> hex string to bytes
        "utf8" -> normal string to UTF-8 bytes
        "raw"  -> bytes/bytearray directly, or str as UTF-8
    """
    if value is None:
        return b""

    if encoding == "bits":
        return _bits_to_bytes(value, name)

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, str):
        if encoding == "hex":
            return bytes.fromhex(value)
        elif encoding in ("utf8", "raw"):
            return value.encode("utf-8")

    raise TypeError(f"{name} must be bytes, bytearray, or str")


def _require_size(data, size, name):
    """
    Require exact byte size.
    No padding is applied.
    """
    if len(data) != size:
        raise ValueError(
            f"{name} must be exactly {size} bytes "
            f"({size * 8} bits), got {len(data)} bytes "
            f"({len(data) * 8} bits)"
        )


def _format_output(data, output_encoding):
    """
    Format output as hex, bytes, or bits.
    """
    if output_encoding == "hex":
        return data.hex()

    if output_encoding == "bytes":
        return data

    if output_encoding == "bits":
        return "".join(f"{byte:08b}" for byte in data)

    raise ValueError("output_encoding must be 'hex', 'bytes', or 'bits'")


def encrypt(
    key,
    nonce,
    plaintext,
    aad="",
    key_encoding="bits",
    nonce_encoding="bits",
    plaintext_encoding="raw",
    aad_encoding="bits",
    output_encoding="hex",
):
    """
    Encrypt using ChaCha20-Poly1305.

    Default frontend input format:
        key   -> bits
        nonce -> bits
        aad   -> bits

    plaintext can be:
        plaintext_encoding="utf8"
        plaintext_encoding="hex"
        plaintext_encoding="bits"
        plaintext_encoding="raw"
    """

    key = _to_bytes(key, key_encoding, "key")
    nonce = _to_bytes(nonce, nonce_encoding, "nonce")
    plaintext = _to_bytes(plaintext, plaintext_encoding, "plaintext")
    aad = _to_bytes(aad, aad_encoding, "aad")

    _require_size(key, KEY_SIZE, "key")
    _require_size(nonce, NONCE_SIZE, "nonce")

    cipher = ChaCha20Poly1305(key)

    full_output = bytes(cipher.encrypt(
        nonce,
        plaintext=plaintext,
        associated_data=aad
    ))

    ciphertext = full_output[:-TAG_SIZE]
    tag = full_output[-TAG_SIZE:]

    return {
        "ciphertext": _format_output(ciphertext, output_encoding),
        "tag": _format_output(tag, output_encoding),
        "output": _format_output(full_output, output_encoding),
    }


def decrypt(
    key,
    nonce,
    ciphertext,
    tag=None,
    aad="",
    key_encoding="bits",
    nonce_encoding="bits",
    ciphertext_encoding="hex",
    tag_encoding="hex",
    aad_encoding="bits",
    output_encoding="bytes",
):
    """
    Decrypt using ChaCha20-Poly1305.

    If tag is given:
        full ciphertext = ciphertext || tag

    If tag is None:
        ciphertext must already be ciphertext || tag
    """

    key = _to_bytes(key, key_encoding, "key")
    nonce = _to_bytes(nonce, nonce_encoding, "nonce")
    ciphertext = _to_bytes(ciphertext, ciphertext_encoding, "ciphertext")
    aad = _to_bytes(aad, aad_encoding, "aad")

    _require_size(key, KEY_SIZE, "key")
    _require_size(nonce, NONCE_SIZE, "nonce")

    if tag is not None:
        tag = _to_bytes(tag, tag_encoding, "tag")

        if len(tag) != TAG_SIZE:
            raise ValueError(
                f"tag must be exactly {TAG_SIZE} bytes "
                f"({TAG_SIZE * 8} bits), got {len(tag)} bytes"
            )

        full_ciphertext = ciphertext + tag
    else:
        full_ciphertext = ciphertext

    cipher = ChaCha20Poly1305(key)

    try:
        plaintext = bytes(cipher.decrypt(
            nonce,
            full_ciphertext,
            associated_data=aad
        ))
    except TagInvalidException:
        raise ValueError(
            "Invalid tag. Wrong key, nonce, AAD, ciphertext, or tag."
        )

    return _format_output(plaintext, output_encoding)


# ============================================================
# Test Vector
# Source: RFC ChaCha20-Poly1305 AEAD test vector
# ============================================================

if __name__ == "__main__":
    key_hex = (
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )

    nonce_hex = "070000004041424344454647"

    aad_hex = "50515253c0c1c2c3c4c5c6c7"

    plaintext_hex = (
        "4c616469657320616e642047656e746c656d656e206f662074686520636c61737320"
        "6f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c7920"
        "6f6e652074697020666f7220746865206675747572652c2073756e73637265656e20"
        "776f756c642062652069742e"
    )

    expected_ciphertext = (
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )

    expected_tag = "1ae10b594f09e26a7e902ecbd0600691"
    expected_output = expected_ciphertext + expected_tag

    key_bits = _hex_to_bits(key_hex)
    nonce_bits = _hex_to_bits(nonce_hex)
    aad_bits = _hex_to_bits(aad_hex)

    encrypted = encrypt(
        key=key_bits,
        nonce=nonce_bits,
        plaintext=plaintext_hex,
        aad=aad_bits,
        plaintext_encoding="hex",
        output_encoding="hex",
    )

    print("ciphertext:", encrypted["ciphertext"])
    print("tag:", encrypted["tag"])
    print("output:", encrypted["output"])

    assert encrypted["ciphertext"] == expected_ciphertext
    assert encrypted["tag"] == expected_tag
    assert encrypted["output"] == expected_output

    decrypted = decrypt(
        key=key_bits,
        nonce=nonce_bits,
        ciphertext=encrypted["ciphertext"],
        tag=encrypted["tag"],
        aad=aad_bits,
        output_encoding="hex",
    )

    print("decrypted:", decrypted)

    assert decrypted == plaintext_hex

    print("ChaCha20-Poly1305 wrapper test passed.")