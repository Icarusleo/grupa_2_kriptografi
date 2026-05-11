"""
SHA-3 test suite — NIST CAVS 19.0 byte-oriented vectors.

Vektör kaynağı: NIST CSRC SHA3 Byte-Oriented Test Vectors
(https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)

Format (CAVS .rsp):
    [L = 224]                ← digest uzunluğu (bit)
    Len = <bit_len>          ← mesaj uzunluğu (byte-hizalı, 8 katı)
    Msg = <hex>              ← mesaj; Len=0 ise placeholder "00"
    MD = <hex>               ← beklenen digest

Monte (NIST sequential MD test):
    Seed = <hex>
    COUNT = j (0..99)
    MD = <hex>
İçsel döngü: MD[0] = Seed; her j için 1000 kere MD = SHA3(MD); seed = MD[1000].

Kullanım:
    python3 test_sha3.py              # ShortMsg + LongMsg KAT (hızlı)
    python3 test_sha3.py --monte      # ek olarak Monte (yavaş, pure-Python)
    python3 test_sha3.py --quick      # her dosyadan ilk 20 vektör (smoke test)
"""

from __future__ import annotations

import os
import sys
import time
import argparse

# Parent (backend/api) dizinini import path'e ekle — sha3_pure modülü oradadır.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sha3_pure import hash_digest  # noqa: E402


SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.join(SCRIPT_DIR, "vectors")

# [L=...] (bit) → algoritma kimliği
L_TO_ALGO = {
    224: "sha3-224",
    256: "sha3-256",
    384: "sha3-384",
    512: "sha3-512",
}


# ── Parser ───────────────────────────────────────────────────────────────────

def _parse_kv_lines(path: str):
    """Yield (key, value) çiftleri, yorum/başlık satırlarını atla."""
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            yield k.strip(), v.strip()


def parse_msg_rsp(path: str) -> list[dict]:
    """ShortMsg / LongMsg .rsp dosyasından (len, msg, md) vektörleri çıkar."""
    vectors: list[dict] = []
    cur: dict = {}
    for k, v in _parse_kv_lines(path):
        if k == "Len":
            cur = {"len_bits": int(v)}
        elif k == "Msg":
            cur["msg_hex"] = v
        elif k == "MD":
            cur["md_hex"] = v.lower()
            vectors.append(cur)
            cur = {}
    return vectors


def parse_monte_rsp(path: str) -> tuple[str, list[str]]:
    """Monte .rsp dosyasından (seed, [md_count_0, md_count_1, ...]) çıkar."""
    seed: str | None = None
    counts: list[tuple[int, str]] = []
    cur_count: int | None = None
    for k, v in _parse_kv_lines(path):
        if k == "Seed":
            seed = v
        elif k == "COUNT":
            cur_count = int(v)
        elif k == "MD" and cur_count is not None:
            counts.append((cur_count, v.lower()))
            cur_count = None
    if seed is None:
        raise ValueError(f"Seed yok: {path}")
    counts.sort(key=lambda x: x[0])
    return seed, [md for _, md in counts]


# ── KAT (ShortMsg / LongMsg) ────────────────────────────────────────────────

def run_msg_kat(algo: str, path: str, *, limit: int | None = None) -> tuple[int, int]:
    """Verilen .rsp dosyasındaki vektörleri çalıştır, (passed, failed) döner."""
    vectors = parse_msg_rsp(path)
    if limit is not None:
        vectors = vectors[:limit]

    passed = 0
    failed = 0
    label  = os.path.basename(path)
    t0     = time.perf_counter()

    for i, vec in enumerate(vectors, 1):
        length_bits = vec["len_bits"]
        # NIST .rsp dosyalarında Len=0 için Msg="00" placeholder konur;
        # gerçek mesaj boş byte dizisidir.
        msg = b"" if length_bits == 0 else bytes.fromhex(vec["msg_hex"])
        assert len(msg) * 8 == length_bits, (
            f"{label} #{i}: Len={length_bits} != msg byte ({len(msg)*8})"
        )

        got = hash_digest(algo, msg).hex()
        if got == vec["md_hex"]:
            passed += 1
        else:
            failed += 1
            if failed <= 3:  # ilk birkaç hatayı raporla
                print(f"  [FAIL] {label} #{i} Len={length_bits}")
                print(f"         expected: {vec['md_hex']}")
                print(f"         got     : {got}")

    elapsed = time.perf_counter() - t0
    total   = passed + failed
    status  = "OK" if failed == 0 else "FAIL"
    print(f"  [{status}] {label:32s} {passed:4d}/{total:4d}  ({elapsed:5.2f}s)")
    return passed, failed


# ── Monte ───────────────────────────────────────────────────────────────────

def run_monte(algo: str, path: str, *, limit: int | None = None) -> tuple[int, int]:
    """NIST SHA-3 Monte testini koştur. 100 COUNT × 1000 hash iter — yavaş."""
    seed_hex, expected_mds = parse_monte_rsp(path)
    if limit is not None:
        expected_mds = expected_mds[:limit]

    md = bytes.fromhex(seed_hex)
    passed = 0
    failed = 0
    label  = os.path.basename(path)
    t0     = time.perf_counter()

    for j, exp_hex in enumerate(expected_mds):
        for _ in range(1000):
            md = hash_digest(algo, md)
        if md.hex() == exp_hex:
            passed += 1
        else:
            failed += 1
            if failed <= 3:
                print(f"  [FAIL] {label} COUNT={j}")
                print(f"         expected: {exp_hex}")
                print(f"         got     : {md.hex()}")
            break  # Monte zincir kırılırsa devamı manasız

    elapsed = time.perf_counter() - t0
    total   = passed + failed
    status  = "OK" if failed == 0 else "FAIL"
    print(f"  [{status}] {label:32s} {passed:4d}/{total:4d}  ({elapsed:5.2f}s)")
    return passed, failed


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="SHA-3 NIST CAVS test runner")
    ap.add_argument("--monte", action="store_true",
                    help="Monte testini de çalıştır (yavaş, pure-Python)")
    ap.add_argument("--quick", action="store_true",
                    help="Her dosyadan ilk 20 vektör (smoke test)")
    ap.add_argument("--only", choices=["short", "long", "monte"],
                    help="Sadece belirtilen tipi koştur")
    args = ap.parse_args()

    if not os.path.isdir(VECTORS_DIR):
        print(f"Vektör dizini bulunamadı: {VECTORS_DIR}", file=sys.stderr)
        return 2

    print("=" * 70)
    print(" SHA-3 NIST CAVS 19.0 Test Suite")
    print("=" * 70)
    print(f"Vektörler  : {VECTORS_DIR}")
    print(f"Mod        : "
          f"{'quick' if args.quick else 'full'}"
          f"{', monte' if args.monte else ''}")
    print()

    limit = 20 if args.quick else None
    total_pass = 0
    total_fail = 0

    types = []
    if args.only is None or args.only == "short":
        types.append(("ShortMsg", run_msg_kat))
    if args.only is None or args.only == "long":
        types.append(("LongMsg", run_msg_kat))
    if args.only == "monte" or (args.monte and args.only is None):
        types.append(("Monte", run_monte))

    for type_name, runner in types:
        print(f"--- {type_name} ---")
        for L, algo in L_TO_ALGO.items():
            fname = f"SHA3_{L}{type_name}.rsp"
            path  = os.path.join(VECTORS_DIR, fname)
            if not os.path.exists(path):
                print(f"  [SKIP] {fname} bulunamadı")
                continue
            p, f = runner(algo, path, limit=limit)
            total_pass += p
            total_fail += f
        print()

    print("=" * 70)
    print(f" Toplam: {total_pass} passed, {total_fail} failed")
    print("=" * 70)
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
