# GOST hash family (this repo)

Goal: **C reference sources** copied from public repositories, plus **standalone Python** that matches those algorithms. UI hooks come later (`hash_registry`, FastAPI routes).

## Versions covered (catalogue rows vs code)

| Row label | Normative refs | Digest | Python module | Vendor C folder |
|-----------|----------------|--------|----------------|-----------------|
| GOST‑94 (`GOST R 34.11‑94`) | [RFC 5831](https://www.rfc-editor.org/rfc/rfc5831.html) | 256 bit | `python_impl/gost_r34_11_94.py` | `vendor/gost_r34_11_94_mjosaarinen/` |
| Streebog‑256 (`GOST R 34.11‑2012`) | [RFC 6986](https://www.rfc-editor.org/rfc/rfc6986.html) | 256 bit | `streebog_*` names in `python_impl/streebog_r34_11_2012.py` (`new('streebog256', ...)`) | `vendor/streebog_r34_11_2012_adegtyarev/` |
| Streebog‑512 (`GOST R 34.11‑2012`) | RFC 6986 | 512 bit | same file (`streebog512`) | same vendor tree |
| `GOST 34.11‑2018` | Updated national edition (often cited 2019‑06‑01) | Typically **same** 256 / 512 outputs as Streebog until norms show different vectors | *No fourth implementation* unless standard PDF diverges—use `streebog256` / `streebog512`. | Often same codebase as 2012; separate C tarball not duplicated here |

## Vendor C origins

- **`vendor/gost_r34_11_94_mjosaarinen/`** — [mjosaarinen/gost-r34.11-94](https://github.com/mjosaarinen/gost-r34.11-94) (`gosthash.c`, `gosthash.h`, `gosttest.c`, `LICENSE`).
- **`vendor/streebog_r34_11_2012_adegtyarev/`** — [adegtyarev/streebog](https://github.com/adegtyarev/streebog) (`gost3411-2012*.c/h`, precalc/ref headers, `LICENSE`, `Makefile`).
- **`vendor/streebog_okazymyrov_C_standard/`** — [okazymyrov/stribog](https://github.com/okazymyrov/stribog) `C/standard/` (+ CLI helpers); `NOTE_LICENSE.txt`.
- **`vendor/streebog_okazymyrov_C_table/`** — same repo, `C/table/` (table-optimised variant).
- **`vendor/linux_crypto_streebog_generic/`** — [torvalds/linux `crypto/streebog_generic.c`](https://github.com/torvalds/linux/blob/master/crypto/streebog_generic.c) (+ `README.txt`: needs kernel headers).
- **`vendor/libgcrypt_cipher_stribog/`** — [gpg/libgcrypt](https://github.com/gpg/libgcrypt) `stribog.c`, `gostr3411-94.c`, `COPYING.LIB` (+ `README.txt`: needs libgcrypt internals).
- **`vendor/gost_engine_openssl/`** — [gost-engine/engine](https://github.com/gost-engine/engine) `gosthash*.c` / `gosthash2012*` (+ `README.txt`).
- **`vendor/gostsum_gpl3_hashes/`** — [AnatolyGeorgievski/gostsum](https://github.com/AnatolyGeorgievski/gostsum) hash subset (`gosthash.c`, `stribog.c`, `hmac.*`, GPL-3).

**Index of further links:** [`vendor/REFERENCE_OTHER_IMPLEMENTATIONS.md`](vendor/REFERENCE_OTHER_IMPLEMENTATIONS.md).

Python modules **`python_impl/*.py`** document these URLs in their module docstrings.

Rebuild on Unix-like systems: enter the vendor folder and `make` (see upstream `README.md`).

## Python implementations

| File | Basis |
|------|--------|
| `python_impl/gost_r34_11_94.py` | Logical port of `gosthash.c` (validated with `gosttest.c` vectors 1–2). |
| `python_impl/streebog_r34_11_2012.py` | Vendored pure-Python from [drobotun/gostcrypto](https://github.com/drobotun/gostcrypto) MIT `gost_34_11_2012.py`, trimmed with `python_impl/_streebog_support.py` (no package import path to `gostcrypto`). Matches published empty-message Streebog digests. |

## Smoke tests (`backend/api` as cwd)

```text
set PYTHONPATH=.
python -m gost.python_impl.gost_r34_11_94
python -m gost.python_impl.streebog_r34_11_2012
```

The Python self-tests include **32 / 64 / 128-bit** message sizes as **4 / 8 / 16**
**zero-bytes** (byte-aligned API), plus chunked `update()` equivalence.

## Next steps (later)

Register `HashPlugin` subclasses wrapping `new_gost94` / `streebog_new` and expose routes; frontend unchanged for now.
