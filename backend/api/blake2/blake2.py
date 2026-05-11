"""
BLAKE2b ve BLAKE2s — saf Python implementation (RFC 7693).

Hazır kütüphane (hashlib, pycryptodome vb.) kullanılmaz.
İki varyant aynı çekirdek `_blake2` fonksiyonu üzerinden parametrelendirilir:
    - BLAKE2b: 64-bit word, 12 round, 128B blok, max 64B digest
    - BLAKE2s: 32-bit word, 10 round,  64B blok, max 32B digest
"""

from __future__ import annotations


# SHA-512 başlangıç sabitleri (BLAKE2b)
IV64 = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)

# SHA-256 başlangıç sabitleri (BLAKE2s)
IV32 = (
    0x6A09E667, 0xBB67AE85,
    0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C,
    0x1F83D9AB, 0x5BE0CD19,
)

# Mesaj kelimesi permütasyonu (12 round için r mod 10 ile döner)
SIGMA = (
    ( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
    (14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3),
    (11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4),
    ( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8),
    ( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13),
    ( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9),
    (12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11),
    (13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10),
    ( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5),
    (10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0),
)


def _rotr(value: int, bits: int, w: int, mask: int) -> int:
    value &= mask
    return ((value >> bits) | (value << (w - bits))) & mask


def _compress(h, block, t, last_block, *, w, rounds, mask, iv, rot):
    r1, r2, r3, r4 = rot
    word_bytes = w // 8

    m = [
        int.from_bytes(block[i * word_bytes:(i + 1) * word_bytes], "little")
        for i in range(16)
    ]

    v = list(h) + list(iv)
    v[12] ^= t & mask
    v[13] ^= (t >> w) & mask
    if last_block:
        v[14] ^= mask

    def G(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & mask
        v[d] = _rotr(v[d] ^ v[a], r1, w, mask)
        v[c] = (v[c] + v[d]) & mask
        v[b] = _rotr(v[b] ^ v[c], r2, w, mask)
        v[a] = (v[a] + v[b] + y) & mask
        v[d] = _rotr(v[d] ^ v[a], r3, w, mask)
        v[c] = (v[c] + v[d]) & mask
        v[b] = _rotr(v[b] ^ v[c], r4, w, mask)

    for r in range(rounds):
        s = SIGMA[r % 10]
        G(0, 4,  8, 12, m[s[ 0]], m[s[ 1]])
        G(1, 5,  9, 13, m[s[ 2]], m[s[ 3]])
        G(2, 6, 10, 14, m[s[ 4]], m[s[ 5]])
        G(3, 7, 11, 15, m[s[ 6]], m[s[ 7]])
        G(0, 5, 10, 15, m[s[ 8]], m[s[ 9]])
        G(1, 6, 11, 12, m[s[10]], m[s[11]])
        G(2, 7,  8, 13, m[s[12]], m[s[13]])
        G(3, 4,  9, 14, m[s[14]], m[s[15]])

    return [(h[i] ^ v[i] ^ v[i + 8]) & mask for i in range(8)]


def _build_param_block(digest_length: int, key_length: int,
                       salt: bytes, person: bytes,
                       param_size: int, salt_max: int) -> bytes:
    """
    RFC 7693 §2.5 parameter block (sequential mode).

    Layout (BLAKE2b 64 byte, BLAKE2s 32 byte):
        offset 0:  digest_length (1)
        offset 1:  key_length    (1)
        offset 2:  fanout        (1)  = 1
        offset 3:  depth         (1)  = 1
        offset 4..7 / 4..11:  leaf_length + node_offset + node_depth + inner_length = 0
        next salt_max bytes:   salt    (sıfır-padded)
        son  salt_max bytes:   person  (sıfır-padded)
    """
    pb = bytearray(param_size)
    pb[0] = digest_length
    pb[1] = key_length
    pb[2] = 1  # fanout
    pb[3] = 1  # depth
    # leaf_length, node_offset, node_depth, inner_length zaten 0
    salt_offset   = param_size - 2 * salt_max
    person_offset = param_size - salt_max
    pb[salt_offset:salt_offset + len(salt)]     = salt
    pb[person_offset:person_offset + len(person)] = person
    return bytes(pb)


def _blake2(message: bytes, digest_length: int, key: bytes,
            salt: bytes, person: bytes, *,
            w: int, rounds: int, block_size: int,
            max_digest: int, max_key: int, max_salt: int,
            iv: tuple, rot: tuple) -> bytes:
    if not (1 <= digest_length <= max_digest):
        raise ValueError(f"digest_length 1..{max_digest} aralığında olmalı")
    if len(key) > max_key:
        raise ValueError(f"key uzunluğu en fazla {max_key} byte")
    if len(salt) > max_salt:
        raise ValueError(f"salt uzunluğu en fazla {max_salt} byte")
    if len(person) > max_salt:
        raise ValueError(f"person uzunluğu en fazla {max_salt} byte")

    mask = (1 << w) - 1
    word_bytes = w // 8
    param_size = 8 * word_bytes  # BLAKE2b 64B, BLAKE2s 32B

    # Parameter block'u IV ile XOR'la, h[]'yi başlat
    pb = _build_param_block(digest_length, len(key), salt, person,
                            param_size, max_salt)
    h = [
        iv[i] ^ int.from_bytes(pb[i * word_bytes:(i + 1) * word_bytes], "little")
        for i in range(8)
    ]

    data = bytearray()
    if key:
        data.extend(key.ljust(block_size, b"\x00"))
    data.extend(message)

    ll = len(message)
    if not data:
        data = bytearray(block_size)
    else:
        pad = (-len(data)) % block_size
        if pad:
            data.extend(b"\x00" * pad)

    n_blocks = len(data) // block_size

    for i in range(n_blocks - 1):
        block = data[i * block_size:(i + 1) * block_size]
        h = _compress(h, block, (i + 1) * block_size, False,
                      w=w, rounds=rounds, mask=mask, iv=iv, rot=rot)

    final_t = ll + (block_size if key else 0)
    last_block = data[(n_blocks - 1) * block_size: n_blocks * block_size]
    h = _compress(h, last_block, final_t, True,
                  w=w, rounds=rounds, mask=mask, iv=iv, rot=rot)

    out = b"".join(int(word & mask).to_bytes(word_bytes, "little") for word in h)
    return out[:digest_length]


def blake2b(message: bytes, digest_length: int = 64,
            key: bytes = b"", salt: bytes = b"", person: bytes = b"") -> bytes:
    return _blake2(
        message, digest_length, key, salt, person,
        w=64, rounds=12, block_size=128,
        max_digest=64, max_key=64, max_salt=16,
        iv=IV64, rot=(32, 24, 16, 63),
    )


def blake2s(message: bytes, digest_length: int = 32,
            key: bytes = b"", salt: bytes = b"", person: bytes = b"") -> bytes:
    return _blake2(
        message, digest_length, key, salt, person,
        w=32, rounds=10, block_size=64,
        max_digest=32, max_key=32, max_salt=8,
        iv=IV32, rot=(16, 12, 8, 7),
    )


if __name__ == "__main__":
    # RFC 7693 test vektörü: BLAKE2b("abc", 64)
    expected_b = (
        "ba80a53f981c4d0d6a2797b69f12f6e9"
        "4c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc95"
        "18d38aa8dbf1925ab92386edd4009923"
    )
    got_b = blake2b(b"abc").hex()
    assert got_b == expected_b, f"BLAKE2b mismatch:\n  got: {got_b}\n  exp: {expected_b}"
    print("[OK] BLAKE2b('abc') doğrulandı")

    # BLAKE2s("abc", 32) — referans vektör (hashlib ile çapraz doğrulandı)
    expected_s = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
    got_s = blake2s(b"abc").hex()
    assert got_s == expected_s, f"BLAKE2s mismatch:\n  got: {got_s}\n  exp: {expected_s}"
    print("[OK] BLAKE2s('abc') doğrulandı")

    # Boş mesaj
    assert blake2b(b"").hex().startswith("786a02f742015903")
    assert blake2s(b"").hex() == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    print("[OK] Boş mesaj vektörleri doğrulandı")

    # Keyed / salt / person — hashlib ile çapraz doğrulanmış vektörler
    import hashlib  # sadece referans karşılaştırma için

    # BLAKE2b keyed (MAC modu)
    h_ref = hashlib.blake2b(b"abc", key=b"key", digest_size=32).hexdigest()
    h_got = blake2b(b"abc", digest_length=32, key=b"key").hex()
    assert h_got == h_ref, f"BLAKE2b keyed mismatch:\n  got: {h_got}\n  exp: {h_ref}"
    print(f"[OK] BLAKE2b keyed (key=b'key', digest=32B) doğrulandı")

    # BLAKE2b salt + person (16 byte sınır)
    salt16 = b"\x01" * 16
    pers16 = b"\x02" * 16
    h_ref = hashlib.blake2b(b"abc", salt=salt16, person=pers16).hexdigest()
    h_got = blake2b(b"abc", salt=salt16, person=pers16).hex()
    assert h_got == h_ref, f"BLAKE2b salt+person mismatch:\n  got: {h_got}\n  exp: {h_ref}"
    print(f"[OK] BLAKE2b salt+person (16B+16B) doğrulandı")

    # BLAKE2s tam parametre seti (key + salt + person, küçük sınırlar)
    salt8 = b"saltsalt"
    pers8 = b"personal"
    h_ref = hashlib.blake2s(b"merhaba", key=b"k", salt=salt8, person=pers8, digest_size=16).hexdigest()
    h_got = blake2s(b"merhaba", digest_length=16, key=b"k", salt=salt8, person=pers8).hex()
    assert h_got == h_ref, f"BLAKE2s full params mismatch:\n  got: {h_got}\n  exp: {h_ref}"
    print(f"[OK] BLAKE2s key+salt+person (digest=16B) doğrulandı")

    # Sınır validasyonu
    for bad in [(blake2b, {"salt": b"\x00" * 17}),
                (blake2s, {"person": b"\x00" * 9}),
                (blake2b, {"key": b"\x00" * 65}),
                (blake2s, {"digest_length": 33})]:
        fn, kwargs = bad
        try:
            fn(b"x", **kwargs)
            raise AssertionError(f"Sınır ihlali yakalanmadı: {fn.__name__} {kwargs}")
        except ValueError:
            pass
    print("[OK] Sınır validasyonu (salt/person/key/digest aşımı) doğrulandı")
