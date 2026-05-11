"""
Bilinen-cevap (known-answer) test vektörleri — MD5 ve SHA-1 saf-Python
implementasyonlarını doğrular.

Kullanım:
    python test_hashes.py            # tüm vektörleri çalıştır, özet tablo bas
    pytest test_hashes.py            # pytest ile (kuruluysa)

Referanslar:
    - MD5  : RFC 1321, Appendix A.5  (Test suite)
    - SHA-1: RFC 3174 / FIPS 180-4   (ve yaygın "fox" vektörleri)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "hash_plugins"))

from md5_plugin import md5, MD5Plugin          # noqa: E402
from sha1_plugin import sha1, SHA1Plugin        # noqa: E402


# (girdi_baytları, beklenen_md5_hex, beklenen_sha1_hex)
VECTORS = [
    (b"",
     "d41d8cd98f00b204e9800998ecf8427e",
     "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    (b"a",
     "0cc175b9c0f1b6a831c399e269772661",
     "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
    (b"abc",
     "900150983cd24fb0d6963f7d28e17f72",
     "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (b"message digest",
     "f96b697d7cb7938d525a2f31aaf161d0",
     "c12252ceda8be8994d5fa0290a47231c1d16aae3"),
    (b"abcdefghijklmnopqrstuvwxyz",
     "c3fcd3d76192e4007dfb496cca67e13b",
     "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "d174ab98d277d9f5a5611c2c9f419d9f",
     "761c457bf73b14d27e9e9265c46f4b4dda11f940"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",  # 56 byte -> çok-bloklu
     "8215ef0796a20bcaaae116d3876c664a",
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    (b"The quick brown fox jumps over the lazy dog",
     "9e107d9d372bb6826bd81d3542a419d6",
     "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
    (b"The quick brown fox jumps over the lazy cog",  # tek harf -> çığ etkisi
     "1055d3e698d289f2af8663725127bd4b",
     "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
    (b"a" * 1_000_000,   # 1 MB -> uzun mesaj / 64-bit uzunluk alanı testi
     "7707d6ae4e027c70eea2a935c2296f21",
     "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
]


def _label(data: bytes) -> str:
    if not data:
        return "(boş)"
    if len(data) > 24:
        return f"<{len(data)} byte>"
    return repr(data.decode("latin-1"))


def test_md5_vectors():
    for data, expected_md5, _ in VECTORS:
        assert md5(data).hex() == expected_md5, f"MD5 hata: {_label(data)}"


def test_sha1_vectors():
    for data, _, expected_sha1 in VECTORS:
        assert sha1(data).hex() == expected_sha1, f"SHA-1 hata: {_label(data)}"


def test_plugin_interface():
    """Eklentilerin HashPlugin sözleşmesine uyduğunu ve metadata'nın doğru olduğunu kontrol et."""
    m, s = MD5Plugin(), SHA1Plugin()
    assert m.id == "md5" and m.digest_size == 16 and m.block_size == 64 and m.rounds == 64
    assert s.id == "sha1" and s.digest_size == 20 and s.block_size == 64 and s.rounds == 80
    assert m.compute_hash(b"abc").hex() == "900150983cd24fb0d6963f7d28e17f72"
    assert s.compute_hash(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"


def _run_standalone() -> int:
    failures = 0
    print(f"{'GİRDİ':22} | {'MD5 (128-bit)':34} | SHA-1 (160-bit)")
    print("-" * 22 + "-+-" + "-" * 34 + "-+-" + "-" * 40)
    for data, expected_md5, expected_sha1 in VECTORS:
        got_md5, got_sha1 = md5(data).hex(), sha1(data).hex()
        ok_md5, ok_sha1 = got_md5 == expected_md5, got_sha1 == expected_sha1
        if not ok_md5:
            failures += 1
        if not ok_sha1:
            failures += 1
        mark = "OK " if (ok_md5 and ok_sha1) else "HATA"
        print(f"{_label(data):22} | {got_md5} | {got_sha1}  [{mark}]")
    print("-" * 100)
    if failures:
        print(f"BAŞARISIZ: {failures} kontrol hatalı.")
        return 1
    print(f"TÜM TESTLER GEÇTİ ({len(VECTORS)} vektör × 2 algoritma).")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
