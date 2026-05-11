"""
Pure-Python Keccak-f[1600] + SHA-3 / SHAKE (NIST FIPS 202).
Hazır kütüphane kullanmadan elden uygulanmıştır.

Test edilebilir hâli: python3 sha3_pure.py (NIST KAT'leri otomatik doğrular)
"""

from __future__ import annotations

# ── Keccak-f[1600] sabitleri ──────────────────────────────────────────────────

ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# ρ adımı için döndürme miktarları — ROTATION_OFFSETS[x][y]
# NIST FIPS 202 Tablo 2 (KeccakRhoOffsets[x + 5y] eşleştirmesi).
ROTATION_OFFSETS = [
    [ 0, 36,  3, 41, 18],   # x=0,  y=0..4
    [ 1, 44, 10, 45,  2],   # x=1
    [62,  6, 43, 15, 61],   # x=2
    [28, 55, 25, 21, 56],   # x=3
    [27, 20, 39,  8, 14],   # x=4
]

MASK64 = 0xFFFFFFFFFFFFFFFF


def _rol64(value: int, shift: int) -> int:
    """64-bit sola dairesel kaydırma."""
    shift &= 63
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def _keccak_f1600(state: list[list[int]]) -> list[list[int]]:
    """24-round Keccak-f[1600] permütasyonu. Durum: 5×5 lane, her lane 64 bit."""
    for r in range(24):
        # θ
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = D[x]
            for y in range(5):
                state[x][y] ^= dx

        # ρ ve π
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol64(state[x][y], ROTATION_OFFSETS[x][y])

        # χ
        for x in range(5):
            for y in range(5):
                state[x][y] = (B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])) & MASK64

        # ι
        state[0][0] ^= ROUND_CONSTANTS[r]
    return state


# ── State <-> byte serialization (lane'ler little-endian) ────────────────────

def _state_to_bytes(state: list[list[int]]) -> bytearray:
    out = bytearray(200)
    for y in range(5):
        for x in range(5):
            off = 8 * (x + 5 * y)
            out[off:off + 8] = state[x][y].to_bytes(8, 'little')
    return out


def _bytes_to_state(buf: bytes | bytearray) -> list[list[int]]:
    state = [[0] * 5 for _ in range(5)]
    for y in range(5):
        for x in range(5):
            off = 8 * (x + 5 * y)
            state[x][y] = int.from_bytes(buf[off:off + 8], 'little')
    return state


# ── Sponge: absorb + squeeze ─────────────────────────────────────────────────

def _keccak_sponge(message: bytes, rate_bytes: int, output_bytes: int, domain: int) -> bytes:
    """
    NIST FIPS 202 sponge: pad10*1 + Keccak-f[1600].
    domain: SHA-3 = 0x06 (suffix 01 + pad10*1 başlangıcı)
            SHAKE = 0x1F (suffix 1111 + pad10*1 başlangıcı)
    """
    # Pad10*1: msg ‖ domain ‖ 0..0 ‖ 0x80. Mesaj rate-1 byte ile bitiyorsa
    # domain ve son 0x80 aynı byte'a düşer → OR'lanır (tek blok), yoksa
    # son byte 0x80 olacak şekilde sıfırla doldurulup yeni bir 0x80 eklenir.
    padded = bytearray(message)
    if len(padded) % rate_bytes == rate_bytes - 1:
        padded.append(domain | 0x80)
    else:
        padded.append(domain)
        while len(padded) % rate_bytes != rate_bytes - 1:
            padded.append(0x00)
        padded.append(0x80)

    state_bytes = bytearray(200)  # 1600 bit = 200 byte sıfırla başla

    # Absorb
    for off in range(0, len(padded), rate_bytes):
        for i in range(rate_bytes):
            state_bytes[i] ^= padded[off + i]
        state = _bytes_to_state(state_bytes)
        state = _keccak_f1600(state)
        state_bytes = _state_to_bytes(state)

    # Squeeze
    out = bytearray()
    while len(out) < output_bytes:
        take = min(rate_bytes, output_bytes - len(out))
        out.extend(state_bytes[:take])
        if len(out) >= output_bytes:
            break
        state = _bytes_to_state(state_bytes)
        state = _keccak_f1600(state)
        state_bytes = _state_to_bytes(state)

    return bytes(out[:output_bytes])


# ── Public API ───────────────────────────────────────────────────────────────

# (rate_bytes, output_bytes, domain) — None output_bytes = XOF
_PARAMS = {
    "sha3-224": (144, 28,  0x06),
    "sha3-256": (136, 32,  0x06),
    "sha3-384": (104, 48,  0x06),
    "sha3-512": ( 72, 64,  0x06),
    "shake-128": (168, None, 0x1F),
    "shake-256": (136, None, 0x1F),
}


def hash_digest(algo_id: str, message: bytes, output_length: int | None = None) -> bytes:
    """
    SHA-3 / SHAKE digest hesapla.
    algo_id ∈ {sha3-224, sha3-256, sha3-384, sha3-512, shake-128, shake-256}.
    output_length sadece SHAKE için, byte cinsinden.
    """
    if algo_id not in _PARAMS:
        raise ValueError(f"Desteklenmeyen hash algoritması: {algo_id}")
    rate_bytes, fixed_len, domain = _PARAMS[algo_id]
    is_xof = fixed_len is None
    if is_xof:
        if output_length is None or output_length < 1:
            raise ValueError("SHAKE için output_length >= 1 olmalı")
        out_len = output_length
    else:
        out_len = fixed_len
    return _keccak_sponge(message, rate_bytes, out_len, domain)


def sha3_224(msg: bytes) -> bytes: return hash_digest("sha3-224", msg)
def sha3_256(msg: bytes) -> bytes: return hash_digest("sha3-256", msg)
def sha3_384(msg: bytes) -> bytes: return hash_digest("sha3-384", msg)
def sha3_512(msg: bytes) -> bytes: return hash_digest("sha3-512", msg)
def shake_128(msg: bytes, n: int) -> bytes: return hash_digest("shake-128", msg, n)
def shake_256(msg: bytes, n: int) -> bytes: return hash_digest("shake-256", msg, n)


# ── Self-test (NIST FIPS 202 KAT) ────────────────────────────────────────────

if __name__ == "__main__":
    import hashlib  # sadece referans karşılaştırma için, üretim yolunda kullanılmaz

    KAT = [
        ("sha3-224", b"",   "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
        ("sha3-224", b"abc","e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
        ("sha3-256", b"",   "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        ("sha3-256", b"abc","3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("sha3-384", b"",   "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"),
        ("sha3-512", b"",   "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
        ("sha3-512", b"abc","b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
    ]
    print("SHA-3 KAT testleri:")
    for algo, msg, expected in KAT:
        got = hash_digest(algo, msg).hex()
        status = "OK" if got == expected else "FAIL"
        print(f"  [{status}] {algo}({msg!r:20s}) = {got[:64]}{'...' if len(got) > 64 else ''}")
        assert got == expected, f"{algo} mismatch"

    # SHAKE KAT'leri
    SHAKE_KAT = [
        ("shake-128", b"", 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
        ("shake-256", b"", 16, "46b9dd2b0ba88d13233b3feb743eeb24"),
        ("shake-256", b"", 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
    ]
    print("\nSHAKE KAT testleri:")
    for algo, msg, n, expected in SHAKE_KAT:
        got = hash_digest(algo, msg, n).hex()
        status = "OK" if got == expected else "FAIL"
        print(f"  [{status}] {algo}({msg!r}, {n}B) = {got}")
        # Bağımsız doğrulama: hashlib ile karşılaştır
        ref = (hashlib.shake_128 if algo == "shake-128" else hashlib.shake_256)(msg).digest(n).hex()
        assert got == ref, f"{algo} hashlib karşılaştırma fail: got={got} ref={ref}"

    # Daha uzun mesaj ve rastgele girdi karşılaştırması
    import os
    print("\nRastgele mesaj karşılaştırma (32 örnek):")
    rng_fail = 0
    for i in range(32):
        n = (i * 37 + 3) % 500
        m = os.urandom(n)
        for algo in ("sha3-224", "sha3-256", "sha3-384", "sha3-512"):
            ours = hash_digest(algo, m).hex()
            ref  = getattr(hashlib, algo.replace("-", "_"))(m).hexdigest()
            if ours != ref:
                print(f"  FAIL {algo} len={n}")
                rng_fail += 1
        for algo, n_out in (("shake-128", 64), ("shake-256", 96)):
            ours = hash_digest(algo, m, n_out).hex()
            ref_obj = (hashlib.shake_128 if algo == "shake-128" else hashlib.shake_256)(m)
            ref  = ref_obj.digest(n_out).hex()
            if ours != ref:
                print(f"  FAIL {algo} len={n}, out={n_out}")
                rng_fail += 1
    print(f"  Tamamlandı, fail sayısı: {rng_fail}")
    print("\nTüm KAT'ler geçti." if rng_fail == 0 else "\nBazı testler başarısız!")
