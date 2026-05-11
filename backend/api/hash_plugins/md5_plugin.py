"""
MD5 hash plugin — pure-Python implementation of RFC 1321.

No external / crypto libraries are used (no `hashlib`); the compression
function is implemented from scratch. Use this file as a template for adding
other cryptographic hash functions: copy it, rename the class, implement
`compute_hash`, and drop it into this folder — the registry auto-discovers it.
"""
import math
import struct

from hash_registry import HashPlugin

# ── Constants ─────────────────────────────────────────────────────────────────

# Per-round left-rotation amounts (RFC 1321, section 3.4)
_S = (
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
)

# Per-round additive constants: K[i] = floor(2**32 * abs(sin(i + 1)))
_K = tuple(int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64))

_MASK32 = 0xFFFFFFFF


def _rotl32(value: int, amount: int) -> int:
    value &= _MASK32
    return ((value << amount) | (value >> (32 - amount))) & _MASK32


def md5(message: bytes) -> bytes:
    """Return the 16-byte MD5 digest of ``message``."""
    # Initial state (little-endian words A, B, C, D)
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    original_bit_len = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF

    # Padding: append 0x80, then 0x00 until length ≡ 56 (mod 64),
    # then the original length as a 64-bit little-endian integer.
    message += b"\x80"
    message += b"\x00" * ((56 - len(message) % 64) % 64)
    message += struct.pack("<Q", original_bit_len)

    for offset in range(0, len(message), 64):
        m = struct.unpack("<16I", message[offset:offset + 64])
        a, b, c, d = a0, b0, c0, d0

        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d & _MASK32))
                g = (7 * i) % 16

            f = (f + a + _K[i] + m[g]) & _MASK32
            a, d, c = d, c, b
            b = (b + _rotl32(f, _S[i])) & _MASK32

        a0 = (a0 + a) & _MASK32
        b0 = (b0 + b) & _MASK32
        c0 = (c0 + c) & _MASK32
        d0 = (d0 + d) & _MASK32

    return struct.pack("<4I", a0, b0, c0, d0)


# ── Plugin definition ─────────────────────────────────────────────────────────

class MD5Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "md5"

    @property
    def name(self) -> str:
        return "MD5"

    @property
    def description(self) -> str:
        return ("Message-Digest Algorithm 5 (RFC 1321). 128-bit özet, 512-bit blok, "
                "64 tur. Kriptografik olarak kırılmıştır; sadece eğitim/karşılaştırma amaçlı.")

    @property
    def digest_size(self) -> int:
        return 16

    @property
    def block_size(self) -> int:
        return 64

    @property
    def rounds(self) -> int:
        return 64

    def compute_hash(self, data: bytes) -> bytes:
        return md5(data)
