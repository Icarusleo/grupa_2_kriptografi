"""
SHA-1 hash plugin — pure-Python implementation of FIPS 180-4 / RFC 3174.

No external / crypto libraries are used (no `hashlib`); the compression
function is implemented from scratch. See ``md5_plugin.py`` for the template
notes — adding a new hash function is just a matter of dropping a similar
file into this folder.
"""
import struct

from hash_registry import HashPlugin

_MASK32 = 0xFFFFFFFF


def _rotl32(value: int, amount: int) -> int:
    value &= _MASK32
    return ((value << amount) | (value >> (32 - amount))) & _MASK32


def sha1(message: bytes) -> bytes:
    """Return the 20-byte SHA-1 digest of ``message``."""
    h0, h1, h2, h3, h4 = (
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    )

    original_bit_len = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF

    # Padding: 0x80, then 0x00 until length ≡ 56 (mod 64),
    # then the original length as a 64-bit big-endian integer.
    message += b"\x80"
    message += b"\x00" * ((56 - len(message) % 64) % 64)
    message += struct.pack(">Q", original_bit_len)

    for offset in range(0, len(message), 64):
        w = list(struct.unpack(">16I", message[offset:offset + 64]))
        for i in range(16, 80):
            w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            if i < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_rotl32(a, 5) + f + e + k + w[i]) & _MASK32
            e, d, c, b, a = d, c, _rotl32(b, 30), a, temp

        h0 = (h0 + a) & _MASK32
        h1 = (h1 + b) & _MASK32
        h2 = (h2 + c) & _MASK32
        h3 = (h3 + d) & _MASK32
        h4 = (h4 + e) & _MASK32

    return struct.pack(">5I", h0, h1, h2, h3, h4)


# ── Plugin definition ─────────────────────────────────────────────────────────

class SHA1Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha1"

    @property
    def name(self) -> str:
        return "SHA-1"

    @property
    def description(self) -> str:
        return ("Secure Hash Algorithm 1 (FIPS 180-4). 160-bit özet, 512-bit blok, "
                "80 tur. Çarpışma saldırılarına karşı güvensizdir; eğitim amaçlı.")

    @property
    def digest_size(self) -> int:
        return 20

    @property
    def block_size(self) -> int:
        return 64

    @property
    def rounds(self) -> int:
        return 80

    def compute_hash(self, data: bytes) -> bytes:
        return sha1(data)
