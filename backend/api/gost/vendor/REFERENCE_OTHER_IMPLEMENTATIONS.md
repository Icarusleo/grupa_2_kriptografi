# Other public GOST hash implementations

This file lists C/C++ and ecosystem implementations. Many are now **mirrored**
under `vendor/` (see each folder’s `README.txt`). Remaining rows are **L** = link only.

Legend: **V** = snapshot in `vendor/`, **L** = not copied (or only partially).

**Also mirrored (2026-05-11):** `linux_crypto_streebog_generic/`, `libgcrypt_cipher_stribog/`,
`gost_engine_openssl/`, `gostsum_gpl3_hashes/`, `streebog_okazymyrov_C_table/`.

---

## GOST R 34.11-94 (256-bit legacy)

| Source | Lang | License (typ.) | Notes |
|--------|------|----------------|--------|
| [mjosaarinen/gost-r34.11-94](https://github.com/mjosaarinen/gost-r34.11-94) | C | MIT | **V** `vendor/gost_r34_11_94_mjosaarinen/`. |
| [gpg/libgcrypt `cipher/gostr3411-94.c`](https://github.com/gpg/libgcrypt/blob/master/cipher/gostr3411-94.c) | C | LGPL-2.1+ | **V** same folder as Streebog: `vendor/libgcrypt_cipher_stribog/gostr3411-94.c`. |
| [AnatolyGeorgievski/gostsum](https://github.com/AnatolyGeorgievski/gostsum) | C | GPL-3.0 | **V** `vendor/gostsum_gpl3_hashes/` (gosthash, stribog, hmac subset). |
| [gost-engine/engine](https://github.com/gost-engine/engine) (OpenSSL engine) | C | See repo `LICENSE` + file headers | **V** `vendor/gost_engine_openssl/` (`gosthash*`, `gosthash2012*`). |
| OpenSSL `_ossl_deprecated_` paths | C | Apache 2.0 (OpenSSL); engine code varies | Historic **ccgost** files appeared in forks (e.g. Chromium OpenSSL snapshots: `engines/ccgost/gosthash.c`). |
| Botan crypto library | C++ | BSD-2-Clause | Ships GOST-era algorithms in some builds (check `botan` docs for `Streebog`/legacy coverage). |

---

## GOST R 34.11-2012 — Streebog-256 / Streebog-512

| Source | Lang | License (typ.) | Notes |
|--------|------|----------------|--------|
| [adegtyarev/streebog](https://github.com/adegtyarev/streebog) | C | BSD-2-Clause (see `LICENSE`) | Already vendored (`vendor/streebog_r34_11_2012_adegtyarev/`). |
| **[okazymyrov/stribog](https://github.com/okazymyrov/stribog)** | **C** | **Unspecified** in repo root | **V** `vendor/streebog_okazymyrov_C_standard/` and `vendor/streebog_okazymyrov_C_table/`; `NOTE_LICENSE.txt`. |
| [Linux kernel `crypto/streebog_generic.c`](https://github.com/torvalds/linux/blob/master/crypto/streebog_generic.c) | C | SPDX GPL-2.0+ OR BSD-2-Clause in file | **V** `vendor/linux_crypto_streebog_generic/` (needs kernel headers). |
| [gpg/libgcrypt `cipher/stribog.c`](https://github.com/gpg/libgcrypt/blob/master/cipher/stribog.c) | C | LGPL-2.1+ | **V** `vendor/libgcrypt_cipher_stribog/` (+ `gostr3411-94.c`, `COPYING.LIB`; needs libgcrypt internals). |
| [mp81ss/streebog](https://github.com/mp81ss/streebog) | C | Inherited from Degtyarev | Maintenance fork / build fixes vs upstream `streebog`. |
| [BearSSL — `src/hash/gost256.c`](https://bearssl.org/) *(if enabled in tree)* | C | MIT | Embedded TLS project; check current tree for GOST hash modules. |
| [ddulesov/pystribog](https://github.com/ddulesov/pystribog) | C + Python ext | Check repo | Fast path via native code; not pure C library. |

---

## GOST 34.11-2018

No widely separate **second** hash algorithm is published as open C source distinct from **34.11-2012** Streebog in the links above. Implementations usually remain **Streebog 256/512** until a normative document proves different test vectors; treat **2018** as a document/versioning layer, not a fifth digest family.

---

## Where Python copies exist (for comparison, not vendored as requirements)

| Project | Notes |
|---------|--------|
| [drobotun/gostcrypto](https://github.com/drobotun/gostcrypto) | MIT; `gosthash` — basis of in-tree `streebog_r34_11_2012.py`. |
| [mosquito/pygost](https://github.com/mosquito/pygost) | GPL-3.0; pure Python GOST suite (94 + 2012). |

---

## Suggested use

- **Compliance / thesis bibliography:** cite RFC 5831, RFC 6986, and the specific Git commit you mirror.  
- **License mixing:** do not merge **GPL** engine code into the same binary as proprietary code without review; **MIT / BSD / LGPL** choices differ.  
- **Verification:** cross-check digests between **mjosaarinen**/**adegtyarev**/**libgcrypt** on the same test strings when extending tests.
