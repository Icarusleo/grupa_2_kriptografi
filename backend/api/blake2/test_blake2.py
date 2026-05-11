"""
BLAKE2 test suite — official BLAKE2 KAT (`blake2-kat.json`).

Vektör kaynağı: BLAKE2 reference repository, `kat/blake2-kat.json`
(https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json)

Format (her giriş):
    {
        "hash": "blake2s" | "blake2b" | "blake2sp" | "blake2bp" | "blake2xs" | "blake2xb",
        "in":   "<hex mesaj>",
        "key":  "<hex anahtar>"    (boş string = unkeyed),
        "out":  "<hex digest>"
    }

Toplam 3072 vektör; bizim implementasyon `blake2s` + `blake2b` destekler
(paralel `*p` ve extensible `*x` varyantları kapsam dışı → atlanır).

Kullanım:
    python3 test_blake2.py            # tüm desteklenen vektörler
    python3 test_blake2.py --quick    # her variant×keyed kombinasyonundan ilk 8
"""

from __future__ import annotations

import json
import os
import sys
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blake2 import blake2b, blake2s  # noqa: E402


SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(SCRIPT_DIR, "vectors", "blake2-kat.json")

SUPPORTED = {
    "blake2b": blake2b,
    "blake2s": blake2s,
}


def load_vectors(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run(vectors: list[dict], *, quick: bool = False) -> tuple[int, int, int]:
    """(passed, failed, skipped) döner."""
    passed = skipped = failed = 0

    # quick mode: her (variant, keyed) kombinasyonundan ilk 8 vektör
    if quick:
        bucket: dict[tuple[str, bool], int] = {}
        filtered = []
        for v in vectors:
            k = (v["hash"], bool(v.get("key")))
            if bucket.get(k, 0) >= 8:
                continue
            bucket[k] = bucket.get(k, 0) + 1
            filtered.append(v)
        vectors = filtered

    by_variant: dict[str, dict[str, int]] = {}
    t0 = time.perf_counter()
    first_fail_logged = 0

    for vec in vectors:
        variant = vec["hash"]
        fn = SUPPORTED.get(variant)
        stat = by_variant.setdefault(variant, {"pass": 0, "fail": 0, "skip": 0})

        if fn is None:
            stat["skip"] += 1
            skipped += 1
            continue

        msg = bytes.fromhex(vec["in"])
        key = bytes.fromhex(vec["key"]) if vec.get("key") else b""
        exp = vec["out"].lower()
        digest_length = len(exp) // 2

        try:
            got = fn(msg, digest_length=digest_length, key=key).hex()
        except Exception as e:
            stat["fail"] += 1
            failed += 1
            if first_fail_logged < 3:
                print(f"  [ERROR] {variant} len(msg)={len(msg)} len(key)={len(key)} "
                      f"digest={digest_length}: {e}")
                first_fail_logged += 1
            continue

        if got == exp:
            stat["pass"] += 1
            passed += 1
        else:
            stat["fail"] += 1
            failed += 1
            if first_fail_logged < 3:
                print(f"  [FAIL] {variant} len(msg)={len(msg)} len(key)={len(key)} "
                      f"digest={digest_length}")
                print(f"         expected: {exp}")
                print(f"         got     : {got}")
                first_fail_logged += 1

    elapsed = time.perf_counter() - t0

    print()
    print(f"{'Variant':12s} {'Pass':>6s} {'Fail':>6s} {'Skip':>6s}")
    print("-" * 36)
    for variant in sorted(by_variant):
        s = by_variant[variant]
        marker = "" if variant in SUPPORTED else "  (destek yok)"
        print(f"{variant:12s} {s['pass']:6d} {s['fail']:6d} {s['skip']:6d}{marker}")
    print()
    print(f"Süre: {elapsed:.2f}s")
    return passed, failed, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description="BLAKE2 KAT test runner")
    ap.add_argument("--quick", action="store_true",
                    help="Her variant×keyed bucket'ından ilk 8 vektör")
    args = ap.parse_args()

    if not os.path.exists(VECTORS_PATH):
        print(f"Vektör dosyası bulunamadı: {VECTORS_PATH}", file=sys.stderr)
        return 2

    print("=" * 60)
    print(" BLAKE2 Official KAT Test Suite")
    print("=" * 60)
    vectors = load_vectors(VECTORS_PATH)
    print(f"Vektörler  : {VECTORS_PATH}")
    print(f"Toplam     : {len(vectors)}")
    print(f"Desteklenen: {', '.join(sorted(SUPPORTED))}")
    print(f"Mod        : {'quick' if args.quick else 'full'}")
    print()

    passed, failed, skipped = run(vectors, quick=args.quick)

    print("=" * 60)
    print(f" Sonuç: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
