"""
GOST R 34.11-94 hash (256-bit digest).

Python port (this file) — logical translation of:
  Markku-Juhani O. Saarinen — gosthash.c / gosthash.h
  https://github.com/mjosaarinen/gost-r34.11-94
  Vendored: ../vendor/gost_r34_11_94_mjosaarinen/ (MIT LICENSE there).

Other independent C sources for the same algorithm (vendored for comparison):
  ../vendor/gost_engine_openssl/gosthash.c — OpenSSL GOST engine
    https://github.com/gost-engine/engine
  ../vendor/libgcrypt_cipher_stribog/gostr3411-94.c — Libgcrypt (LGPL; needs
    g10lib.h, gost.h, etc. to build inside libgcrypt)
    https://github.com/gpg/libgcrypt/blob/master/cipher/gostr3411-94.c
  ../vendor/gostsum_gpl3_hashes/gosthash.c — gostsum project (GPL-3+)
    https://github.com/AnatolyGeorgievski/gostsum

Normative spec summary: https://www.rfc-editor.org/rfc/rfc5831.html

Message length is arbitrary; compression uses 32-byte (256-bit) blocks.

This API accepts **whole bytes** only. Short inputs of **32, 64, 128 bits** are
represented as **4, 8, 16** zero-bytes (see `_test_short_bit_aligned_messages`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

_U32 = 0xFFFFFFFF


def _u32(x: int) -> int:
    return x & _U32


# Precomputed S-box tables (filled by _init_tables once)
gost_sbox_1: List[int] = [0] * 256
gost_sbox_2: List[int] = [0] * 256
gost_sbox_3: List[int] = [0] * 256
gost_sbox_4: List[int] = [0] * 256
_TABLES_READY = False


def _init_tables() -> None:
    global _TABLES_READY
    if _TABLES_READY:
        return
    sbox = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    ]
    i = 0
    for a in range(16):
        ax = sbox[1][a] << 15
        bx = sbox[3][a] << 23
        cx = sbox[5][a]
        cx = _u32((cx >> 1) | (cx << 31))
        dx = sbox[7][a] << 7
        for b in range(16):
            gost_sbox_1[i] = _u32(ax | (sbox[0][b] << 11))
            gost_sbox_2[i] = _u32(bx | (sbox[2][b] << 19))
            gost_sbox_3[i] = _u32(cx | (sbox[4][b] << 27))
            gost_sbox_4[i] = _u32(dx | (sbox[6][b] << 3))
            i += 1
    assert i == 256
    globals()["_TABLES_READY"] = True


def _encrypt_round(r: int, l: int, k1: int, k2: int) -> tuple[int, int]:
    t = _u32(k1 + r)
    l = _u32(l ^ (
        gost_sbox_1[t & 0xFF]
        ^ gost_sbox_2[(t >> 8) & 0xFF]
        ^ gost_sbox_3[(t >> 16) & 0xFF]
        ^ gost_sbox_4[t >> 24]
    ))
    t = _u32(k2 + l)
    r = _u32(r ^ (
        gost_sbox_1[t & 0xFF]
        ^ gost_sbox_2[(t >> 8) & 0xFF]
        ^ gost_sbox_3[(t >> 16) & 0xFF]
        ^ gost_sbox_4[t >> 24]
    ))
    return r, l


def _gost_encrypt(key: List[int], r: int, l: int) -> tuple[int, int]:
    r, l = _encrypt_round(r, l, key[0], key[1])
    r, l = _encrypt_round(r, l, key[2], key[3])
    r, l = _encrypt_round(r, l, key[4], key[5])
    r, l = _encrypt_round(r, l, key[6], key[7])
    r, l = _encrypt_round(r, l, key[0], key[1])
    r, l = _encrypt_round(r, l, key[2], key[3])
    r, l = _encrypt_round(r, l, key[4], key[5])
    r, l = _encrypt_round(r, l, key[6], key[7])
    r, l = _encrypt_round(r, l, key[0], key[1])
    r, l = _encrypt_round(r, l, key[2], key[3])
    r, l = _encrypt_round(r, l, key[4], key[5])
    r, l = _encrypt_round(r, l, key[6], key[7])
    r, l = _encrypt_round(r, l, key[7], key[6])
    r, l = _encrypt_round(r, l, key[5], key[4])
    r, l = _encrypt_round(r, l, key[3], key[2])
    r, l = _encrypt_round(r, l, key[1], key[0])
    return l, r  # swap: t = r; r = l; l = t in C


def _compress(h: List[int], m: List[int]) -> None:
    u = h[:]
    v = m[:]
    s = [0] * 8
    key = [0] * 8
    for i in (0, 2, 4, 6):
        w = [_u32(u[j] ^ v[j]) for j in range(8)]
        key[0] = _u32(
            (w[0] & 0x000000FF)
            | ((w[2] & 0x000000FF) << 8)
            | ((w[4] & 0x000000FF) << 16)
            | ((w[6] & 0x000000FF) << 24)
        )
        key[1] = _u32(
            ((w[0] & 0x0000FF00) >> 8)
            | (w[2] & 0x0000FF00)
            | ((w[4] & 0x0000FF00) << 8)
            | ((w[6] & 0x0000FF00) << 16)
        )
        key[2] = _u32(
            ((w[0] & 0x00FF0000) >> 16)
            | ((w[2] & 0x00FF0000) >> 8)
            | (w[4] & 0x00FF0000)
            | ((w[6] & 0x00FF0000) << 8)
        )
        key[3] = _u32(
            ((w[0] & 0xFF000000) >> 24)
            | ((w[2] & 0xFF000000) >> 16)
            | ((w[4] & 0xFF000000) >> 8)
            | (w[6] & 0xFF000000)
        )
        key[4] = _u32(
            (w[1] & 0x000000FF)
            | ((w[3] & 0x000000FF) << 8)
            | ((w[5] & 0x000000FF) << 16)
            | ((w[7] & 0x000000FF) << 24)
        )
        key[5] = _u32(
            ((w[1] & 0x0000FF00) >> 8)
            | (w[3] & 0x0000FF00)
            | ((w[5] & 0x0000FF00) << 8)
            | ((w[7] & 0x0000FF00) << 16)
        )
        key[6] = _u32(
            ((w[1] & 0x00FF0000) >> 16)
            | ((w[3] & 0x00FF0000) >> 8)
            | (w[5] & 0x00FF0000)
            | ((w[7] & 0x00FF0000) << 8)
        )
        key[7] = _u32(
            ((w[1] & 0xFF000000) >> 24)
            | ((w[3] & 0xFF000000) >> 16)
            | ((w[5] & 0xFF000000) >> 8)
            | (w[7] & 0xFF000000)
        )
        r = _u32(h[i])
        l = _u32(h[i + 1])
        r, l = _gost_encrypt(key, r, l)
        s[i] = r
        s[i + 1] = l
        if i == 6:
            break

        ln = _u32(u[0] ^ u[2])
        rn = _u32(u[1] ^ u[3])
        u[0] = u[2]
        u[1] = u[3]
        u[2] = u[4]
        u[3] = u[5]
        u[4] = u[6]
        u[5] = u[7]
        u[6] = ln
        u[7] = rn
        if i == 2:
            u[0] = _u32(u[0] ^ 0xFF00FF00)
            u[1] = _u32(u[1] ^ 0xFF00FF00)
            u[2] = _u32(u[2] ^ 0x00FF00FF)
            u[3] = _u32(u[3] ^ 0x00FF00FF)
            u[4] = _u32(u[4] ^ 0x00FFFF00)
            u[5] = _u32(u[5] ^ 0xFF0000FF)
            u[6] = _u32(u[6] ^ 0x000000FF)
            u[7] = _u32(u[7] ^ 0xFF00FFFF)

        l = v[0]
        r = v[2]
        v[0] = v[4]
        v[2] = v[6]
        v[4] = _u32(l ^ r)
        v[6] = _u32(v[0] ^ r)

        l = v[1]
        r = v[3]
        v[1] = v[5]
        v[3] = v[7]
        v[5] = _u32(l ^ r)
        v[7] = _u32(v[1] ^ r)

    u[0] = _u32(m[0] ^ s[6])
    u[1] = _u32(m[1] ^ s[7])
    u[2] = _u32(
        m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF)
        ^ (s[1] & 0xFFFF) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16)
        ^ (s[7] & 0xFFFF0000) ^ (s[7] >> 16)
    )
    u[3] = _u32(
        m[3] ^ (s[0] & 0xFFFF) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
        ^ (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16)
        ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF)
        ^ (s[7] << 16) ^ (s[7] >> 16)
    )
    u[4] = _u32(
        m[4] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[0] >> 16)
        ^ (s[1] & 0xFFFF0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16)
        ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16)
        ^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16)
    )
    u[5] = _u32(
        m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF0000)
        ^ (s[1] & 0xFFFF) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16)
        ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[6] << 16)
        ^ (s[6] >> 16) ^ (s[7] & 0xFFFF0000) ^ (s[7] << 16) ^ (s[7] >> 16)
    )
    u[6] = _u32(
        m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16)
        ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6]
        ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16)
    )
    u[7] = _u32(
        m[7] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
        ^ (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16)
        ^ (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF)
        ^ (s[7] << 16) ^ (s[7] >> 16)
    )

    v[0] = _u32(h[0] ^ (u[1] << 16) ^ (u[0] >> 16))
    v[1] = _u32(h[1] ^ (u[2] << 16) ^ (u[1] >> 16))
    v[2] = _u32(h[2] ^ (u[3] << 16) ^ (u[2] >> 16))
    v[3] = _u32(h[3] ^ (u[4] << 16) ^ (u[3] >> 16))
    v[4] = _u32(h[4] ^ (u[5] << 16) ^ (u[4] >> 16))
    v[5] = _u32(h[5] ^ (u[6] << 16) ^ (u[5] >> 16))
    v[6] = _u32(h[6] ^ (u[7] << 16) ^ (u[6] >> 16))
    v[7] = _u32(
        h[7] ^ (u[0] & 0xFFFF0000) ^ (u[0] << 16) ^ (u[7] >> 16)
        ^ (u[1] & 0xFFFF0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xFFFF0000)
    )

    h[0] = _u32(
        (v[0] & 0xFFFF0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16)
        ^ (v[1] & 0xFFFF0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16)
        ^ (v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16)
        ^ (v[7] & 0xFFFF)
    )
    h[1] = _u32(
        (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xFFFF0000) ^ (v[1] & 0xFFFF)
        ^ v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16)
        ^ (v[6] << 16) ^ v[6] ^ (v[7] & 0xFFFF0000) ^ (v[7] >> 16)
    )
    h[2] = _u32(
        (v[0] & 0xFFFF) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16)
        ^ (v[1] & 0xFFFF0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3]
        ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0xFFFF)
        ^ (v[7] << 16) ^ (v[7] >> 16)
    )
    h[3] = _u32(
        (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xFFFF0000)
        ^ (v[1] & 0xFFFF0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16)
        ^ v[2] ^ (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16)
        ^ (v[6] << 16) ^ (v[7] & 0xFFFF) ^ (v[7] >> 16)
    )
    h[4] = _u32(
        (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2]
        ^ (v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16)
        ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16)
    )
    h[5] = _u32(
        (v[0] << 16) ^ (v[0] & 0xFFFF0000) ^ (v[1] << 16) ^ (v[1] >> 16)
        ^ (v[1] & 0xFFFF0000) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3]
        ^ (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16)
        ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xFFFF0000)
    )
    h[6] = _u32(
        v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^ (v[4] >> 16)
        ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16)
        ^ v[6] ^ (v[7] << 16) ^ v[7]
    )
    h[7] = _u32(
        v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16)
        ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5]
        ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7]
    )


def _buf_to_words_le(buf: bytes, off: int) -> List[int]:
    m = []
    j = off
    for _ in range(8):
        a = _u32(
            buf[j]
            | (buf[j + 1] << 8)
            | (buf[j + 2] << 16)
            | (buf[j + 3] << 24)
        )
        m.append(a)
        j += 4
    return m


@dataclass
class GostHash94:
    sum: List[int] = field(default_factory=lambda: [0] * 8)
    hash: List[int] = field(default_factory=lambda: [0] * 8)
    length: List[int] = field(default_factory=lambda: [0] * 8)
    partial: bytearray = field(default_factory=lambda: bytearray(32))
    partial_bytes: int = 0

    def reset(self) -> None:
        self.sum = [0] * 8
        self.hash = [0] * 8
        self.length = [0] * 8
        self.partial = bytearray(32)
        self.partial_bytes = 0

    def _bytes_block(self, buf: bytes, bits: int) -> None:
        m = _buf_to_words_le(buf, 0)
        carry = 0
        for i in range(8):
            a = m[i]
            tot = a + carry + self.sum[i]
            self.sum[i] = _u32(tot)
            carry = tot >> 32
        _compress(self.hash, m)
        self.length[0] = _u32(self.length[0] + bits)
        if self.length[0] < bits:
            self.length[1] = _u32(self.length[1] + 1)

    def update(self, data: bytes | bytearray) -> None:
        _init_tables()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('bytes required')
        data = bytes(data)
        i = self.partial_bytes
        j = 0
        n = len(data)
        while i < 32 and j < n:
            self.partial[i] = data[j]
            i += 1
            j += 1
        if i < 32:
            self.partial_bytes = i
            return
        self._bytes_block(bytes(self.partial), 256)
        while j + 32 <= n:
            self._bytes_block(data[j : j + 32], 256)
            j += 32
        self.partial = bytearray(32)
        k = 0
        while j < n:
            self.partial[k] = data[j]
            k += 1
            j += 1
        self.partial_bytes = k

    def digest(self) -> bytes:
        _init_tables()
        if self.partial_bytes > 0:
            tail = self.partial[: self.partial_bytes] + bytes(32 - self.partial_bytes)
            self._bytes_block(tail, self.partial_bytes * 8)
            self.partial_bytes = 0
        len_block = [0] * 8
        len_block[0] = _u32(self.length[0])
        len_block[1] = _u32(self.length[1])
        _compress(self.hash, len_block)
        _compress(self.hash, self.sum[:])
        out = bytearray(32)
        o = 0
        for i in range(8):
            a = self.hash[i]
            out[o] = a & 0xFF
            out[o + 1] = (a >> 8) & 0xFF
            out[o + 2] = (a >> 16) & 0xFF
            out[o + 3] = (a >> 24) & 0xFF
            o += 4
        return bytes(out)

    def hexdigest(self) -> str:
        return self.digest().hex()


def new_gost94(data: bytes | bytearray = b'') -> GostHash94:
    _init_tables()
    ctx = GostHash94()
    if data:
        ctx.update(data)
    return ctx


def _self_test() -> None:
    t1 = bytes([
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2C,
        0x20, 0x6C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x3D,
        0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73,
    ])
    e1 = bytes([
        0xB1, 0xC4, 0x66, 0xD3, 0x75, 0x19, 0xB8, 0x2E,
        0x83, 0x19, 0x81, 0x9F, 0xF3, 0x25, 0x95, 0xE0,
        0x47, 0xA2, 0x8C, 0xB6, 0xF8, 0x3E, 0xFF, 0x1C,
        0x69, 0x16, 0xA8, 0x15, 0xA6, 0x37, 0xFF, 0xFA,
    ])
    t2 = bytes([
        0x53, 0x75, 0x70, 0x70, 0x6F, 0x73, 0x65, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x6F, 0x72, 0x69, 0x67,
        0x69, 0x6E, 0x61, 0x6C, 0x20, 0x6D, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65, 0x20, 0x68, 0x61, 0x73,
        0x20, 0x6C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x20,
        0x3D, 0x20, 0x35, 0x30, 0x20, 0x62, 0x79, 0x74,
        0x65, 0x73,
    ])
    e2 = bytes([
        0x47, 0x1A, 0xBA, 0x57, 0xA6, 0x0A, 0x77, 0x0D,
        0x3A, 0x76, 0x13, 0x06, 0x35, 0xC1, 0xFB, 0xEA,
        0x4E, 0xF1, 0x4D, 0xE5, 0x1F, 0x78, 0xB4, 0xAE,
        0x57, 0xDD, 0x89, 0x3B, 0x62, 0xF5, 0x52, 0x08,
    ])
    h = new_gost94(t1)
    assert h.digest() == e1, 'GOST-94 test vector 1 failed'
    h = new_gost94(t2)
    assert h.digest() == e2, 'GOST-94 test vector 2 failed'


def _test_short_bit_aligned_messages() -> None:
    """
    32 / 64 / 128-bit message lengths via byte-aligned payloads (zeros).

    Regression digests produced by this implementation (2026-05-11); cross-check
    with vendor C if needed. Also verifies split update() matches one-shot.
    """
    expected = {
        4: 'f9a759730a22b5ef0bd94a73cb9ec4d7bd001bd6c54201cdd851d869d1265961',
        8: 'aabf32c5cbb0f893d12d37166e1c8e23e8695ca72f80be1f848aa09f9518d339',
        16: '2e3604acfce0e93b3ba2f0127313ba4acf1ef35958c45eded84760fff27e86b0',
    }
    for nbytes, want_hex in expected.items():
        z = bytes(nbytes)
        got = new_gost94(z).hexdigest()
        assert got == want_hex, f'GOST-94 {nbytes * 8}-bit (zero) digest mismatch'
        for split in range(1, nbytes):
            a = GostHash94()
            a.update(z[:split])
            a.update(z[split:])
            assert a.hexdigest() == want_hex, f'GOST-94 chunk split={split} nbytes={nbytes}'


if __name__ == '__main__':
    _self_test()
    _test_short_bit_aligned_messages()
    print('gost_r34_11_94: self-test OK')
