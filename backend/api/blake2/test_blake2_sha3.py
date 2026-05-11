"""
KAT (Known Answer Tests) - SHA-3 ve BLAKE2 implementasyonlari

Kaynak test vektorleri:
  SHA-3 : NIST FIPS 202
  BLAKE2: RFC 7693 + resmi blake2.net referans ciktilari

Calistirma:
    cd backend/api
    python -m hash_plugins.test_kat
  ya da
    python hash_plugins/test_kat.py
"""

import sys
import os
import io
import hashlib

# Windows terminal UTF-8 zorla
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from hash_plugins.sha3_plugin import (
    SHA3_224Plugin, SHA3_256Plugin, SHA3_384Plugin, SHA3_512Plugin
)
from hash_plugins.blake2_plugin import (
    BLAKE2bPlugin, BLAKE2b_256Plugin, BLAKE2sPlugin
)

# Renk kodlari (terminal ciktisi)
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

passed = 0
failed = 0


def check(label: str, result: str, expected: str):
    global passed, failed
    ok = result.lower() == expected.lower()
    if ok:
        passed += 1
        print(f"  {GREEN}PASS{RESET}  {label}")
    else:
        failed += 1
        print(f"  {RED}FAIL{RESET}  {label}")
        print(f"         Beklenen  : {expected}")
        print(f"         Hesaplanan: {result}")


def section(title: str):
    print(f"\n{BOLD}{CYAN}{'-'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'-'*60}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# SHA-3 NIST KAT Vektörleri
# Kaynak: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bittestvectors.zip
# ─────────────────────────────────────────────────────────────────────────────

SHA3_KAT: dict[str, list[tuple[bytes, str]]] = {
    "sha3-224": [
        # (girdi, beklenen_hex)
        (b"",
         "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
        (b"abc",
         "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"),
        # 1 milyon 'a' — rate sınır testi (144 byte = SHA3-224 rate)
        (b"a" * 1_000_000,
         "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"),
    ],
    "sha3-256": [
        (b"",
         "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc",
         "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"),
        (b"a" * 1_000_000,
         "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
    ],
    "sha3-384": [
        (b"",
         "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"),
        (b"abc",
         "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"),
        (b"a" * 1_000_000,
         "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"),
    ],
    "sha3-512": [
        (b"",
         "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
        (b"abc",
         "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
         "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
         b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"),
        (b"a" * 1_000_000,
         "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"),
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# BLAKE2 KAT Vektörleri
# Resmi blake2.net ve RFC 7693 referans çıktıları (anahtarsız mod)
# ─────────────────────────────────────────────────────────────────────────────

BLAKE2_KAT: dict[str, list[tuple[bytes, str]]] = {
    "blake2b": [
        (b"",
         "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
         "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
        (b"abc",
         "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
         "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
        (b"The quick brown fox jumps over the lazy dog",
         "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673"
         "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"),
        # 2 bloktan fazla (>128 byte)
        (b"a" * 200,
         None),   # None → hashlib referansına karşılaştır
        (b"a" * 1_000_000,
         None),
    ],
    "blake2b-256": [
        (b"",
         "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
        (b"abc",
         "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
        (b"The quick brown fox jumps over the lazy dog",
         "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9"),
        (b"a" * 200,   None),
        (b"a" * 1_000_000, None),
    ],
    "blake2s": [
        (b"",
         "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
        (b"abc",
         "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
        (b"The quick brown fox jumps over the lazy dog",
         "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"),
        (b"a" * 200,   None),
        (b"a" * 1_000_000, None),
    ],
}


def run_sha3_kat():
    """SHA-3 KAT — önce sabit NIST vektörleri, sonra hashlib karşılaştırması"""
    plugins = {
        "sha3-224": SHA3_224Plugin(),
        "sha3-256": SHA3_256Plugin(),
        "sha3-384": SHA3_384Plugin(),
        "sha3-512": SHA3_512Plugin(),
    }
    hashlib_name = {
        "sha3-224": "sha3_224",
        "sha3-256": "sha3_256",
        "sha3-384": "sha3_384",
        "sha3-512": "sha3_512",
    }

    for alg, vectors in SHA3_KAT.items():
        section(f"SHA-3 KAT >> {alg.upper()}")
        plugin = plugins[alg]

        for msg, expected in vectors:
            label_msg = repr(msg[:24]) + ("…" if len(msg) > 24 else "")
            result = plugin.compute_hash(msg).hex()

            # Sabit vektörü doğrula
            check(f"NIST  {label_msg}", result, expected)

        # Ek hashlib karşılaştırması (50+ farklı mesaj uzunluğu)
        section(f"SHA-3 Hashlib Ref >> {alg.upper()}")
        test_msgs = (
            [b""] +
            [bytes([i]) for i in range(256)] +
            [b"\x00" * n for n in [1, 63, 64, 65, 127, 128, 129, 135, 136, 137, 255, 256]] +
            [b"\xff" * n for n in [1, 71, 72, 103, 104, 143, 144]] +
            [b"hello world", b"kriptografi", b"SHA-3 test mesaji 1234567890!@#$"]
        )
        all_ok = True
        for msg in test_msgs:
            result = plugin.compute_hash(msg).hex()
            ref = hashlib.new(hashlib_name[alg], msg).hexdigest()
            if result != ref:
                check(f"Hashlib  {repr(msg[:20])}", result, ref)
                all_ok = False
        if all_ok:
            print(f"  {GREEN}PASS{RESET}  Hashlib ref — {len(test_msgs)} mesaj tümü doğru")
        else:
            global failed
            failed += len(test_msgs)


def run_blake2_kat():
    """BLAKE2 KAT — resmi vektörler + hashlib karşılaştırması"""
    plugins = {
        "blake2b":     BLAKE2bPlugin(),
        "blake2b-256": BLAKE2b_256Plugin(),
        "blake2s":     BLAKE2sPlugin(),
    }

    for alg, vectors in BLAKE2_KAT.items():
        section(f"BLAKE2 KAT >> {alg.upper()}")
        plugin = plugins[alg]

        for msg, expected in vectors:
            label_msg = repr(msg[:24]) + ("…" if len(msg) > 24 else "")
            result = plugin.compute_hash(msg).hex()

            if expected is not None:
                check(f"Resmi  {label_msg}", result, expected.replace(" ", ""))
            else:
                # None → hashlib referansına göre kontrol et
                ds = plugin.digest_size
                if "blake2s" in alg:
                    ref = hashlib.blake2s(msg, digest_size=ds).hexdigest()
                else:
                    ref = hashlib.blake2b(msg, digest_size=ds).hexdigest()
                check(f"Hashlib  {label_msg}", result, ref)

        # Hashlib kapsamlı karşılaştırma
        section(f"BLAKE2 Hashlib Ref >> {alg.upper()}")
        ds = plugin.digest_size
        test_msgs = (
            [b""] +
            [bytes([i]) for i in range(256)] +
            [b"\x00" * n for n in [1, 63, 64, 65, 127, 128, 129, 255, 256, 512]] +
            [b"\xff" * n for n in [1, 63, 64, 65, 127, 128]] +
            [b"merhaba dunya", b"kriptografi testi 0123456789", b"a" * 300]
        )
        all_ok = True
        for msg in test_msgs:
            result = plugin.compute_hash(msg).hex()
            if "blake2s" in alg:
                ref = hashlib.blake2s(msg, digest_size=ds).hexdigest()
            else:
                ref = hashlib.blake2b(msg, digest_size=ds).hexdigest()
            if result != ref:
                check(f"Hashlib  {repr(msg[:20])}", result, ref)
                all_ok = False
        if all_ok:
            print(f"  {GREEN}PASS{RESET}  Hashlib ref — {len(test_msgs)} mesaj tümü doğru")
        else:
            global failed
            failed += len(test_msgs)


def run_api_endpoint_kat():
    """
    FastAPI endpoint KAT — /api/v1/hash/compute ile uçtan uca test.
    Backend çalışmıyorsa atlanır.
    """
    import urllib.request
    import json

    section("API Endpoint KAT >> /api/v1/hash/compute")
    base = "http://127.0.0.1:8000"

    try:
        urllib.request.urlopen(f"{base}/api/v1/health", timeout=2)
    except Exception:
        print(f"  {YELLOW}ATLA{RESET}  Backend çalışmıyor, endpoint testleri atlandı.")
        return

    cases = [
        ("sha3-256",   "abc",   "utf8",  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("sha3-512",   "",      "utf8",  "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
        ("blake2b",    "abc",   "utf8",  "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                                         "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
        ("blake2b-256","abc",   "utf8",  "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
        ("blake2s",    "abc",   "utf8",  "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
        ("sha3-224",   "616263","hex",   "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),  # hex "abc"
    ]

    for alg, val, enc, expected in cases:
        payload = json.dumps({
            "algorithm_id": alg,
            "data": {"value": val, "encoding": enc},
            "output_encoding": "hex"
        }).encode()
        req = urllib.request.Request(
            f"{base}/api/v1/hash/compute",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
            result = resp["hash"]["hex"]
            check(f"POST {alg}  [{enc}:{repr(val[:16])}]", result, expected.replace(" ", ""))
        except Exception as e:
            global failed
            failed += 1
            print(f"  {RED}FAIL{RESET}  POST {alg}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Ana çalıştırıcı
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{BOLD}{'='*60}")
    print("  KAT - SHA-3 ve BLAKE2 Implementasyon Testi")
    print(f"{'='*60}{RESET}")

    run_sha3_kat()
    run_blake2_kat()
    run_api_endpoint_kat()

    # Sonuc ozeti
    total = passed + failed
    print(f"\n{BOLD}{'='*60}{RESET}")
    if failed == 0:
        print(f"{BOLD}{GREEN}  SONUC: {passed}/{total} test GECTI  [OK]{RESET}")
    else:
        print(f"{BOLD}{RED}  SONUC: {passed}/{total} GECTI - {failed} BASARISIZ  [FAIL]{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    sys.exit(0 if failed == 0 else 1)
