import base64

from hc256 import HC256


# ============================================================
# Frontend Developer Usage Manual
# ============================================================
#
# HC-128 is a stream cipher.
#
# It uses:
#   key   -> exactly 128 bits / 16 bytes
#   nonce -> exactly 128 bits / 16 bytes
#
# HC-128 does NOT use:
#   - AAD
#   - tag
#   - authentication
#
# Encryption and decryption are the same XOR operation:
#   ciphertext = plaintext  XOR keystream
#   plaintext  = ciphertext XOR keystream
#
# Frontend should send key and nonce as BIT STRINGS by default.
#
# Example bit string:
#   "0100000101000010" means bytes b"AB"
#
# No padding is applied in this wrapper.
# Key and nonce must already have correct length.
#
# ============================================================


KEY_SIZE = 32      # 128 bits
NONCE_SIZE = 32    # 128 bits


def _bits_to_bytes(bit_string, name="value"):
    """
    Convert a bit string like '01010101' to bytes.

    Spaces and underscores are allowed:
        '0101 0101'
        '0101_0101'
    """
    if not isinstance(bit_string, str):
        raise TypeError(f"{name} must be a bit string")

    bit_string = bit_string.replace(" ", "").replace("_", "").replace("\n", "")

    if bit_string == "":
        return b""

    if any(ch not in "01" for ch in bit_string):
        raise ValueError(f"{name} must contain only 0 and 1")

    if len(bit_string) % 8 != 0:
        raise ValueError(f"{name} bit length must be a multiple of 8")

    return int(bit_string, 2).to_bytes(len(bit_string) // 8, byteorder="big")


def _hex_to_bits(hex_string):
    """
    Helper used for tests.
    Converts hex string to bit string.
    """
    raw = bytes.fromhex(hex_string)
    return "".join(f"{byte:08b}" for byte in raw)


def _to_bytes(value, encoding="raw", name="value"):
    """
    Convert input to bytes.

    Supported encodings:
        "bits"   -> bit string to bytes
        "hex"    -> hex string to bytes
        "utf8"   -> normal string to UTF-8 bytes
        "base64" -> base64 string to bytes
        "raw"    -> bytes/bytearray directly, or str as UTF-8
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
            value = value.replace(" ", "").replace("\n", "")
            if len(value) % 2 != 0:
                value = "0" + value
            return bytes.fromhex(value) if value else b""

        if encoding == "utf8" or encoding == "raw":
            return value.encode("utf-8")

        if encoding == "base64":
            return base64.b64decode(value)

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
    Format output.
    """
    if output_encoding == "hex":
        return data.hex()

    if output_encoding == "bytes":
        return data

    if output_encoding == "bits":
        return "".join(f"{byte:08b}" for byte in data)

    if output_encoding == "base64":
        return base64.b64encode(data).decode("ascii")

    if output_encoding == "utf8":
        return data.decode("utf-8", errors="replace")

    raise ValueError(
        "output_encoding must be 'hex', 'bytes', 'bits', 'base64', or 'utf8'"
    )


class HC128Wrapper:
    """
    Easy HC-128 wrapper.

    Default frontend input:
        key   -> bits
        nonce -> bits

    Data can be:
        data_encoding="utf8"
        data_encoding="hex"
        data_encoding="bits"
        data_encoding="base64"
        data_encoding="raw"
    """

    def __init__(
        self,
        key,
        nonce,
        key_encoding="bits",
        nonce_encoding="bits",
    ):
        key = _to_bytes(key, key_encoding, "key")
        nonce = _to_bytes(nonce, nonce_encoding, "nonce")

        _require_size(key, KEY_SIZE, "key")
        _require_size(nonce, NONCE_SIZE, "nonce")

        self.key = key
        self.nonce = nonce

    def crypt(
        self,
        data,
        data_encoding="raw",
        output_encoding="hex",
    ):
        """
        HC-128 encryption/decryption core.

        Since HC-128 is a stream cipher:
            encrypt(data) == decrypt(data)
        """
        data = _to_bytes(data, data_encoding, "data")

        cipher = HC256(self.key, self.nonce)
        result = cipher.crypt(data)

        return _format_output(result, output_encoding)

    def encrypt(
        self,
        plaintext,
        plaintext_encoding="raw",
        output_encoding="hex",
    ):
        ciphertext = self.crypt(
            plaintext,
            data_encoding=plaintext_encoding,
            output_encoding=output_encoding,
        )

        return {
            "ciphertext": ciphertext,
        }

    def decrypt(
        self,
        ciphertext,
        ciphertext_encoding="hex",
        output_encoding="bytes",
    ):
        plaintext = self.crypt(
            ciphertext,
            data_encoding=ciphertext_encoding,
            output_encoding=output_encoding,
        )

        return {
            "plaintext": plaintext,
        }


def encrypt(
    key,
    nonce,
    plaintext,
    key_encoding="bits",
    nonce_encoding="bits",
    plaintext_encoding="raw",
    output_encoding="hex",
):
    """
    Functional helper for encryption.
    """
    cipher = HC128Wrapper(
        key=key,
        nonce=nonce,
        key_encoding=key_encoding,
        nonce_encoding=nonce_encoding,
    )

    return cipher.encrypt(
        plaintext=plaintext,
        plaintext_encoding=plaintext_encoding,
        output_encoding=output_encoding,
    )


def decrypt(
    key,
    nonce,
    ciphertext,
    key_encoding="bits",
    nonce_encoding="bits",
    ciphertext_encoding="hex",
    output_encoding="bytes",
):
    """
    Functional helper for decryption.
    """
    cipher = HC128Wrapper(
        key=key,
        nonce=nonce,
        key_encoding=key_encoding,
        nonce_encoding=nonce_encoding,
    )

    return cipher.decrypt(
        ciphertext=ciphertext,
        ciphertext_encoding=ciphertext_encoding,
        output_encoding=output_encoding,
    )


# ============================================================
# Test Vector
# HC-128 zero key / zero IV first 64 keystream bytes
# Encrypting 64 zero bytes should produce this keystream.
# ============================================================

if __name__ == "__main__":
    key_hex = "00" * 16
    nonce_hex = "00" * 16

    key_bits = _hex_to_bits(key_hex)
    nonce_bits = _hex_to_bits(nonce_hex)

    plaintext_hex = "00" * 64

    expected_ciphertext = (
        "82001573a003fd3b7fd72ffb0eaf63aa"
        "c62f12deb629dca72785a66268ec758b"
        "1edb36900560898178e0ad009abf1f49"
        "1330dc1c246e3d6cb264f6900271d59c"
    )

    encrypted = encrypt(
        key=key_bits,
        nonce=nonce_bits,
        plaintext=plaintext_hex,
        plaintext_encoding="hex",
        output_encoding="hex",
    )

    print("ciphertext:", encrypted["ciphertext"])

    assert encrypted["ciphertext"] == expected_ciphertext

    decrypted = decrypt(
        key=key_bits,
        nonce=nonce_bits,
        ciphertext=encrypted["ciphertext"],
        ciphertext_encoding="hex",
        output_encoding="hex",
    )

    print("decrypted:", decrypted["plaintext"])

    assert decrypted["plaintext"] == plaintext_hex

    # Smaller practical test
    encrypted2 = encrypt(
        key=key_bits,
        nonce=nonce_bits,
        plaintext="patates",
        plaintext_encoding="utf8",
        output_encoding="hex",
    )

    decrypted2 = decrypt(
        key=key_bits,
        nonce=nonce_bits,
        ciphertext=encrypted2["ciphertext"],
        ciphertext_encoding="hex",
        output_encoding="utf8",
    )

    print("patates ciphertext:", encrypted2["ciphertext"])
    print("patates decrypted:", decrypted2["plaintext"])

    assert decrypted2["plaintext"] == "patates"

    print("HC-128 wrapper test passed.")