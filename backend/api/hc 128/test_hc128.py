"""
HC-128 test suite — eSTREAM reference vectors (hc128.txt)
DLL signature: void hc128_encrypt(key*, iv*, in*, out*, uint64 len)
"""

import ctypes
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DLL_PATH   = os.path.join(SCRIPT_DIR, "hc128.dll")
TXT_PATH   = os.path.join(SCRIPT_DIR, "hc128.txt")

# ── DLL loader ────────────────────────────────────────────────────────────────

lib    = None
DLL_OK = False

try:
    lib = ctypes.CDLL(DLL_PATH)
    lib.hc128_encrypt.restype  = None
    lib.hc128_encrypt.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
    ]
    DLL_OK = True
except Exception as e:
    print(f"[WARN] DLL yüklenemedi: {e}")
    print("[INFO] Windows DLL'i Linux'ta çalıştırmak için Wine gerekebilir.")


def hc128_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """HC-128 encrypt/decrypt (aynı işlem)."""
    if not data:
        return b""
    assert len(key) == 16 and len(iv) == 16
    key_buf = (ctypes.c_uint8 * 16).from_buffer_copy(key)
    iv_buf  = (ctypes.c_uint8 * 16).from_buffer_copy(iv)
    in_buf  = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    out_buf = (ctypes.c_uint8 * len(data))()
    lib.hc128_encrypt(key_buf, iv_buf, in_buf, out_buf, len(data))
    return bytes(out_buf)


# ── Test vector parser ────────────────────────────────────────────────────────

def parse_vectors(path: str) -> list[dict]:
    """Parse eSTREAM test vector file into list of dicts."""
    vectors = []
    current: dict = {}

    def _flush():
        if current.get("key") and current.get("iv") and "plaintext" in current and "ciphertext" in current:
            vectors.append(dict(current))

    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line == "#":
                _flush()
                current.clear()
                continue
            if ":" not in line:
                continue
            field, _, val = line.partition(":")
            field = field.strip().lower()
            val   = val.strip().replace(" ", "")
            if field == "key":
                current["key"] = val
            elif field == "iv":
                current["iv"] = val
            elif field == "plaintext":
                current["plaintext"] = val
            elif field == "ciphertext":
                current["ciphertext"] = val
            elif field == "comment":
                current["comment"] = val.strip()

    _flush()
    return vectors


# ── Test runner ───────────────────────────────────────────────────────────────

def run_tests() -> None:
    vectors = parse_vectors(TXT_PATH)

    print("=" * 60)
    print("           HC-128 TEST SUITE")
    print("=" * 60)
    print(f"Toplam vektör: {len(vectors)}")
    if not DLL_OK:
        print("\n[SKIP] DLL yüklenemedi — testler atlanıyor.")
        print("       Windows ortamında çalıştırın veya Wine kullanın.")
        return

    passed = 0
    failed = 0

    for i, vec in enumerate(vectors, 1):
        key        = bytes.fromhex(vec["key"])
        iv         = bytes.fromhex(vec["iv"])
        plaintext  = bytes.fromhex(vec["plaintext"])
        expected   = bytes.fromhex(vec["ciphertext"])

        try:
            result = hc128_crypt(key, iv, plaintext)
            ok     = result == expected

            msg_len = len(plaintext)
            label   = f"Test {i:3d} ({msg_len:3d}-byte msg)"

            if ok:
                print(f"{label}: PASSED")
                passed += 1
            else:
                print(f"{label}: FAILED")
                print(f"  Expected : {expected.hex()}")
                print(f"  Got      : {result.hex()}")
                failed += 1

        except Exception as e:
            print(f"Test {i:3d}: ERROR — {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed}/{len(vectors)} tests passed", end="")
    if failed:
        print(f"  ({failed} FAILED)")
    else:
        print()

    # Decrypt round-trip check (encrypt again should restore plaintext)
    print()
    print("--- Round-trip (şifre çözme) kontrolü ---")
    rt_pass = 0
    for i, vec in enumerate(vectors[:5], 1):
        key       = bytes.fromhex(vec["key"])
        iv        = bytes.fromhex(vec["iv"])
        plaintext = bytes.fromhex(vec["plaintext"])
        ct        = hc128_crypt(key, iv, plaintext)
        recovered = hc128_crypt(key, iv, ct)
        ok        = recovered == plaintext
        print(f"Round-trip {i}: {'PASSED' if ok else 'FAILED'}")
        if ok:
            rt_pass += 1

    if rt_pass == 5:
        print("Tüm round-trip testleri başarılı.")


if __name__ == "__main__":
    run_tests()
