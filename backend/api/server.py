"""
KriptoFlow Backend — FastAPI
DLL'ler: grain.dll, gift_cofb.dll, libisap.dll, ascon.dll, xoodyak_aead.dll,
         salsa20.dll, hc128.dll
Python: chacha20poly1305_wrapper, rabbit/Rabbit_Cipher

Çalıştırma:
    cd backend/api
    pip install fastapi uvicorn
    uvicorn server:app --reload --port 8000

CLI:
    python server.py salsa20-cli --interactive
    python server.py chacha20poly1305-cli --interactive
"""

import argparse
import base64
import ctypes
import struct
import os
import sys
from pathlib import Path
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from hash_registry import HashRegistry

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.resolve()

# ── Rabbit import ─────────────────────────────────────────────────────────────

_RABBIT_AVAILABLE = False
_RabbitCipher = None

try:
    sys.path.insert(0, str(BASE_DIR / 'rabbit'))
    from Rabbit_Cipher import Rabbit as _RabbitCipher  # type: ignore
    _RABBIT_AVAILABLE = True
    print("[OK] Rabbit_Cipher yüklendi")
except Exception as _e:
    print(f"[WARN] Rabbit_Cipher import edilemedi: {_e}")

# ── HC-256 import ─────────────────────────────────────────────────────────────

_HC256_AVAILABLE = False
_HC256Class = None

try:
    sys.path.insert(0, str(BASE_DIR / 'hc256'))
    from hc256 import HC256 as _HC256Class  # type: ignore
    _HC256_AVAILABLE = True
    print("[OK] HC256 yüklendi")
except Exception as _e:
    print(f"[WARN] HC256 import edilemedi: {_e}")

# ── RC4 import ───────────────────────────────────────────────────────────────

_RC4_AVAILABLE = False
_RC4KSA        = None
_RC4PRGA       = None
_rc4_test_fn   = None

try:
    sys.path.insert(0, str(BASE_DIR / 'rc4'))
    from rc4 import KSA as _RC4KSA, PRGA as _RC4PRGA, test as _rc4_test_fn  # type: ignore
    _RC4_AVAILABLE = True
    print("[OK] RC4 yüklendi")
except Exception as _e:
    print(f"[WARN] RC4 import edilemedi: {_e}")

# ── ChaCha20-Poly1305 import ───────────────────────────────────────────────────

try:
    from chacha20poly1305_wrapper import encrypt as chacha20poly1305_encrypt_impl
    from chacha20poly1305_wrapper import decrypt as chacha20poly1305_decrypt_impl
    CHACHA20POLY1305_AVAILABLE    = True
    CHACHA20POLY1305_IMPORT_ERROR = None
    print("[OK] chacha20poly1305_wrapper yüklendi")
except Exception as _e:
    chacha20poly1305_encrypt_impl = None  # type: ignore
    chacha20poly1305_decrypt_impl = None  # type: ignore
    CHACHA20POLY1305_AVAILABLE    = False
    CHACHA20POLY1305_IMPORT_ERROR = str(_e)
    print(f"[WARN] chacha20poly1305_wrapper import edilemedi: {_e}")


# ══════════════════════════════════════════════════════════════════════════════
# DLL Loader — Generic NIST AEAD API Wrapper
# ══════════════════════════════════════════════════════════════════════════════

class AEADAlgorithm:
    """
    NIST AEAD API'yi uygulayan herhangi bir DLL için genel sarmalayıcı.

    DLL imzaları (NIST AEAD standart API):
        int crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)
        int crypto_aead_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k)
    """

    def __init__(self, dll_name: str, key_bytes: int, nonce_bytes: int, tag_bytes: int, display_name: str):
        self.key_bytes   = key_bytes
        self.nonce_bytes = nonce_bytes
        self.tag_bytes   = tag_bytes
        self.display_name = display_name
        self.available   = False
        self.lib         = None
        self._load(dll_name)

    def _load(self, dll_name: str):
        dll_path = BASE_DIR / dll_name
        if not dll_path.exists():
            print(f"[WARN] {dll_name} bulunamadı: {dll_path}")
            return
        try:
            self.lib = ctypes.CDLL(str(dll_path))
            # Encrypt signature
            self.lib.crypto_aead_encrypt.restype  = ctypes.c_int
            self.lib.crypto_aead_encrypt.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte),    # c      (out)
                ctypes.POINTER(ctypes.c_ulonglong),# clen   (out)
                ctypes.POINTER(ctypes.c_ubyte),    # m
                ctypes.c_ulonglong,                # mlen
                ctypes.POINTER(ctypes.c_ubyte),    # ad
                ctypes.c_ulonglong,                # adlen
                ctypes.POINTER(ctypes.c_ubyte),    # nsec (NULL)
                ctypes.POINTER(ctypes.c_ubyte),    # npub (nonce)
                ctypes.POINTER(ctypes.c_ubyte),    # k (key)
            ]
            # Decrypt signature
            self.lib.crypto_aead_decrypt.restype  = ctypes.c_int
            self.lib.crypto_aead_decrypt.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte),    # m      (out)
                ctypes.POINTER(ctypes.c_ulonglong),# mlen   (out)
                ctypes.POINTER(ctypes.c_ubyte),    # nsec (NULL)
                ctypes.POINTER(ctypes.c_ubyte),    # c
                ctypes.c_ulonglong,                # clen
                ctypes.POINTER(ctypes.c_ubyte),    # ad
                ctypes.c_ulonglong,                # adlen
                ctypes.POINTER(ctypes.c_ubyte),    # npub (nonce)
                ctypes.POINTER(ctypes.c_ubyte),    # k (key)
            ]
            self.available = True
            print(f"[OK] {dll_name} yüklendi ({self.display_name})")
        except Exception as e:
            print(f"[ERR] {dll_name} yüklenemedi: {e}")

    # ── helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _to_buf(data: bytes) -> ctypes.Array:
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    @staticmethod
    def _null_ptr() -> ctypes.c_void_p:
        return ctypes.cast(None, ctypes.POINTER(ctypes.c_ubyte))

    # ── encrypt ────────────────────────────────────────────────────────────────

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, tag)"""
        if not self.available:
            raise RuntimeError(f"{self.display_name} DLL mevcut değil")

        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar uzunluğu: {len(key)}B (beklenen {self.key_bytes}B)")
        if len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz nonce uzunluğu: {len(nonce)}B (beklenen {self.nonce_bytes}B)")

        m_buf     = self._to_buf(plaintext) if plaintext else (ctypes.c_ubyte * 0)()
        ad_buf    = self._to_buf(ad)        if ad        else (ctypes.c_ubyte * 0)()
        key_buf   = self._to_buf(key)
        nonce_buf = self._to_buf(nonce)
        nsec      = self._null_ptr()

        max_c = len(plaintext) + self.tag_bytes
        c_buf = (ctypes.c_ubyte * max_c)()
        clen  = ctypes.c_ulonglong(0)

        ret = self.lib.crypto_aead_encrypt(
            c_buf, ctypes.byref(clen),
            m_buf, len(plaintext),
            ad_buf, len(ad),
            nsec,
            nonce_buf,
            key_buf,
        )
        if ret != 0:
            raise RuntimeError(f"Şifreleme başarısız (kod {ret})")

        raw       = bytes(c_buf[:clen.value])
        ciphertext = raw[:len(plaintext)]
        tag        = raw[len(plaintext):]
        return ciphertext, tag

    # ── decrypt ────────────────────────────────────────────────────────────────

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, ad: bytes) -> bytes:
        """Returns plaintext or raises on auth failure"""
        if not self.available:
            raise RuntimeError(f"{self.display_name} DLL mevcut değil")

        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar uzunluğu: {len(key)}B")
        if len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz nonce uzunluğu: {len(nonce)}B")

        # NIST API: c = ciphertext || tag
        c_with_tag = ciphertext + tag
        c_buf      = self._to_buf(c_with_tag)
        ad_buf     = self._to_buf(ad)        if ad else (ctypes.c_ubyte * 0)()
        key_buf    = self._to_buf(key)
        nonce_buf  = self._to_buf(nonce)
        nsec       = self._null_ptr()

        max_m = len(ciphertext)
        m_buf = (ctypes.c_ubyte * max_m)() if max_m else (ctypes.c_ubyte * 0)()
        mlen  = ctypes.c_ulonglong(0)

        ret = self.lib.crypto_aead_decrypt(
            m_buf, ctypes.byref(mlen),
            nsec,
            c_buf, len(c_with_tag),
            ad_buf, len(ad) if ad else 0,
            nonce_buf,
            key_buf,
        )
        if ret != 0:
            raise ValueError("Kimlik doğrulama başarısız — tag uyuşmuyor")

        return bytes(m_buf[:mlen.value])


# ── Salsa20 stream cipher (DLL) ──────────────────────────────────────────────

class Salsa20Algorithm:
    """
    Salsa20 DLL sarmalayıcısı.
    DLL imzası: int s20_crypt(key, keylen_enum, nonce, stream_index, buf, buflen)
    128 veya 256-bit key, 64-bit nonce, tag yok.
    """
    S20_SUCCESS  = 0
    S20_KEYLEN_256 = 0
    S20_KEYLEN_128 = 1

    key_bytes    = 32   # varsayılan 256-bit; 16-byte da kabul edilir
    nonce_bytes  = 8
    tag_bytes    = 0
    display_name = "Salsa20"

    def __init__(self, dll_name: str):
        self.available = False
        self.lib       = None
        self._load(dll_name)

    def _load(self, dll_name: str):
        dll_path = BASE_DIR / dll_name
        if not dll_path.exists():
            print(f"[WARN] {dll_name} bulunamadı: {dll_path}")
            return
        try:
            self.lib = ctypes.CDLL(str(dll_path))
            self.lib.s20_crypt.restype  = ctypes.c_int
            self.lib.s20_crypt.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte),  # key
                ctypes.c_int,                    # keylen enum
                ctypes.POINTER(ctypes.c_ubyte),  # nonce
                ctypes.c_uint32,                 # stream_index
                ctypes.POINTER(ctypes.c_ubyte),  # buf (in-place)
                ctypes.c_uint32,                 # buflen
            ]
            self.available = True
            print(f"[OK] {dll_name} yüklendi (Salsa20)")
        except Exception as e:
            print(f"[ERR] {dll_name} yüklenemedi: {e}")

    @staticmethod
    def _to_buf(data: bytes) -> ctypes.Array:
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    def _resolve_key_enum(self, key: bytes) -> int:
        if len(key) == 32:
            return self.S20_KEYLEN_256
        if len(key) == 16:
            return self.S20_KEYLEN_128
        raise ValueError("Key 16 byte (128-bit) veya 32 byte (256-bit) olmalı")

    def crypt(self, key: bytes, nonce: bytes, data: bytes, stream_index: int = 0) -> bytes:
        if not self.available:
            raise RuntimeError("Salsa20 DLL mevcut değil")
        if len(nonce) != 8:
            raise ValueError("Nonce 8 byte (64-bit) olmalı")
        if not (0 <= stream_index <= 0xFFFFFFFF):
            raise ValueError("stream_index 0 ile 2^32-1 arasında olmalı")
        if len(data) > 0xFFFFFFFF:
            raise ValueError("Veri uzunluğu en fazla 2^32-1 byte olabilir")

        key_enum  = self._resolve_key_enum(key)
        key_buf   = self._to_buf(key)
        nonce_buf = self._to_buf(nonce)
        data_buf  = self._to_buf(data) if data else (ctypes.c_ubyte * 0)()

        ret = self.lib.s20_crypt(
            key_buf,
            key_enum,
            nonce_buf,
            ctypes.c_uint32(stream_index),
            data_buf,
            ctypes.c_uint32(len(data)),
        )
        if ret != self.S20_SUCCESS:
            raise RuntimeError(f"s20_crypt başarısız (kod {ret})")

        return bytes(data_buf[:len(data)])


# ── HC-128 stream cipher (DLL) ────────────────────────────────────────────────

class HC128Algorithm:
    """
    HC-128 stream cipher via hc128.dll.
    DLL signature: void hc128_encrypt(key, iv, in, out, len)
    128-bit key, 128-bit IV, no tag.
    """
    key_bytes    = 16
    nonce_bytes  = 16
    tag_bytes    = 0
    display_name = "HC-128"

    def __init__(self):
        self.available = False
        self.lib       = None
        self._load()

    def _load(self):
        dll_path = BASE_DIR / 'hc 128' / 'hc128.dll'
        if not dll_path.exists():
            print(f"[WARN] hc128.dll bulunamadı: {dll_path}")
            return
        try:
            self.lib = ctypes.CDLL(str(dll_path))
            self.lib.hc128_encrypt.restype  = None
            self.lib.hc128_encrypt.argtypes = [
                ctypes.POINTER(ctypes.c_uint8),  # key
                ctypes.POINTER(ctypes.c_uint8),  # iv
                ctypes.POINTER(ctypes.c_uint8),  # in
                ctypes.POINTER(ctypes.c_uint8),  # out
                ctypes.c_uint64,                 # len
            ]
            self.available = True
            print("[OK] hc128.dll yüklendi (HC-128)")
        except Exception as e:
            print(f"[ERR] hc128.dll yüklenemedi: {e}")

    def _crypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        if not data:
            return b""
        key_buf = (ctypes.c_uint8 * 16).from_buffer_copy(key)
        iv_buf  = (ctypes.c_uint8 * 16).from_buffer_copy(iv)
        in_buf  = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        out_buf = (ctypes.c_uint8 * len(data))()
        self.lib.hc128_encrypt(key_buf, iv_buf, in_buf, out_buf, len(data))
        return bytes(out_buf)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, _ad: bytes) -> tuple[bytes, bytes]:
        if not self.available:
            raise RuntimeError("HC-128 DLL mevcut değil")
        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar: {len(key)}B (beklenen 16B)")
        if len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz IV: {len(nonce)}B (beklenen 16B)")
        return self._crypt(key, nonce, plaintext), b""

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, _tag: bytes, _ad: bytes) -> bytes:
        if not self.available:
            raise RuntimeError("HC-128 DLL mevcut değil")
        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar: {len(key)}B")
        if len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz IV: {len(nonce)}B")
        return self._crypt(key, nonce, ciphertext)


# ── HC-256 stream cipher ──────────────────────────────────────────────────────

class HC256Algorithm:
    """
    HC-256 pure-Python stream cipher.
    256-bit key, 256-bit IV, no tag.
    """
    key_bytes    = 32
    nonce_bytes  = 32
    tag_bytes    = 0
    display_name = "HC-256"
    backend      = "Python"

    def __init__(self):
        self.available = _HC256_AVAILABLE

    def _crypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        if not data:
            return b""
        return _HC256Class(key, iv).crypt(data)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, _ad: bytes) -> tuple[bytes, bytes]:
        if not self.available:
            raise RuntimeError("HC-256 mevcut değil")
        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar: {len(key)}B (beklenen 32B)")
        if len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz IV: {len(nonce)}B (beklenen 32B)")
        return self._crypt(key, nonce, plaintext), b""

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, _tag: bytes, _ad: bytes) -> bytes:
        if not self.available:
            raise RuntimeError("HC-256 mevcut değil")
        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar: {len(key)}B")
        if len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz IV: {len(nonce)}B")
        return self._crypt(key, nonce, ciphertext)


# ── RC4 stream cipher ─────────────────────────────────────────────────────────

class RC4Algorithm:
    """
    RC4 pure-Python stream cipher.
    Variable-length key (1-256 bytes), no IV, no tag.
    key_bytes=0 and nonce_bytes=0 signal handle_encrypt to skip size validation.
    """
    key_bytes    = 0   # variable — skip strict size check
    nonce_bytes  = 0   # no IV
    tag_bytes    = 0
    display_name = "RC4"
    backend      = "Python"

    def __init__(self):
        self.available = _RC4_AVAILABLE

    def _crypt(self, key: bytes, data: bytes) -> bytes:
        if not data:
            return b""
        S  = _RC4KSA(list(key))
        ks = _RC4PRGA(S)
        return bytes([b ^ next(ks) for b in data])

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, _ad: bytes) -> tuple[bytes, bytes]:
        if not self.available:
            raise RuntimeError("RC4 mevcut değil")
        if len(key) == 0:
            raise ValueError("RC4 key boş olamaz")
        return self._crypt(key, plaintext), b""

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, _tag: bytes, _ad: bytes) -> bytes:
        if not self.available:
            raise RuntimeError("RC4 mevcut değil")
        if len(key) == 0:
            raise ValueError("RC4 key boş olamaz")
        return self._crypt(key, ciphertext)


# ── Rabbit stream cipher ──────────────────────────────────────────────────────

class RabbitAlgorithm:
    key_bytes   = 16
    nonce_bytes = 8   # 64-bit IV (optional — opsiyonel ama burada zorunlu tutuyoruz)
    tag_bytes   = 0
    display_name = "Rabbit"
    available   = _RABBIT_AVAILABLE

    @staticmethod
    def _crypt(key: bytes, data: bytes, iv: bytes) -> bytes:
        """Rabbit encrypt = decrypt (XOR keystream)"""
        if not data:
            return b""
        # rabbit_wrapper.py'den alınan byte-order düzeltme mantığı
        internal_key = key[::-1]
        internal_iv  = iv[::-1] if iv else b""
        cipher = _RabbitCipher(internal_key, internal_iv)
        num_blocks = (len(data) + 15) // 16
        raw_ks = cipher.crypt(b"\x00" * (num_blocks * 16))
        fixed_ks = bytearray()
        for i in range(0, len(raw_ks), 16):
            fixed_ks.extend(raw_ks[i:i + 16][::-1])
        return bytes(d ^ k for d, k in zip(data, fixed_ks))

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, _ad: bytes) -> tuple[bytes, bytes]:
        if not self.available:
            raise RuntimeError("Rabbit mevcut değil")
        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar: {len(key)}B (beklenen 16B)")
        if nonce and len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz IV: {len(nonce)}B (beklenen 8B)")
        return self._crypt(key, plaintext, nonce), b""

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, _tag: bytes, _ad: bytes) -> bytes:
        if not self.available:
            raise RuntimeError("Rabbit mevcut değil")
        if len(key) != self.key_bytes:
            raise ValueError(f"Geçersiz anahtar: {len(key)}B (beklenen 16B)")
        if nonce and len(nonce) != self.nonce_bytes:
            raise ValueError(f"Geçersiz IV: {len(nonce)}B (beklenen 8B)")
        return self._crypt(key, ciphertext, nonce)


# ── Algorithm registry ────────────────────────────────────────────────────────

ALGOS = {
    "grain128aead": AEADAlgorithm("grain.dll",         16, 12,  8, "Grain-128 AEAD"),
    "gift-cofb":    AEADAlgorithm("gift_cofb.dll",     16, 16, 16, "GIFT-COFB"),
    "isap":         AEADAlgorithm("libisap.dll",        16, 16, 16, "ISAP"),
    "ascon":        AEADAlgorithm("ascon.dll",          20, 16, 16, "ASCON-80pq"),  # 160-bit key
    "xoodyak":      AEADAlgorithm("xoodyak_aead.dll",  16, 16, 16, "XOODYAK"),
    "hc-128":       HC128Algorithm(),
    "hc-256":       HC256Algorithm(),
    "rc4":          RC4Algorithm(),
    "rabbit":       RabbitAlgorithm(),
}

SALSA20 = Salsa20Algorithm("salsa20.dll")


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic models
# ══════════════════════════════════════════════════════════════════════════════

InputEncoding  = Literal["hex", "utf8", "base64", "bits"]
OutputEncoding = Literal["hex", "base64", "bits", "utf8"]


class EncodedValue(BaseModel):
    value: str
    encoding: InputEncoding = "hex"


class EncryptRequest(BaseModel):
    key: EncodedValue
    nonce: EncodedValue
    plaintext: EncodedValue
    associated_data: EncodedValue = EncodedValue(value="", encoding="hex")
    output_encoding: OutputEncoding = "hex"
    include_core_input_preview: bool = False
    include_normalized_inputs: bool = False


class DecryptRequest(BaseModel):
    key: EncodedValue
    nonce: EncodedValue
    ciphertext: EncodedValue
    tag: EncodedValue = EncodedValue(value="", encoding="hex")  # stream cipher'lar için opsiyonel
    associated_data: EncodedValue = EncodedValue(value="", encoding="hex")
    output_encoding: OutputEncoding = "hex"
    include_core_input_preview: bool = False
    include_normalized_inputs: bool = False


class Salsa20Request(BaseModel):
    key: EncodedValue
    nonce: EncodedValue
    data: EncodedValue
    output_encoding: OutputEncoding = "hex"
    stream_index: int = 0
    include_normalized_inputs: bool = False

    @field_validator("stream_index")
    @classmethod
    def validate_stream_index(cls, value: int) -> int:
        if not (0 <= value <= 0xFFFFFFFF):
            raise ValueError("stream_index 0 ile 2^32-1 arasında olmalı")
        return value


class HashRequest(BaseModel):
    algorithm_id: str
    data: EncodedValue
    output_encoding: OutputEncoding = "hex"


# ══════════════════════════════════════════════════════════════════════════════
# Encoding helpers
# ══════════════════════════════════════════════════════════════════════════════

def decode_input(ev: EncodedValue) -> bytes:
    """EncodedValue → bytes"""
    v = ev.value
    match ev.encoding:
        case "hex":
            v = v.replace(" ", "").replace("\n", "")
            if len(v) % 2:
                v = "0" + v
            return bytes.fromhex(v) if v else b""
        case "utf8":
            return v.encode("utf-8")
        case "base64":
            return base64.b64decode(v)
        case "bits":
            # MSB-first bit string
            v = v.replace(" ", "")
            n = int(v, 2) if v else 0
            length = (len(v) + 7) // 8
            return n.to_bytes(length, "big")
        case _:
            raise ValueError(f"Bilinmeyen kodlama: {ev.encoding}")


def normalized(data: bytes, output_encoding: str = "hex") -> dict:
    """bytes → NormalizedBytes dict"""
    hex_str   = data.hex()
    b64_str   = base64.b64encode(data).decode()
    bits_str  = "".join(f"{b:08b}" for b in data)
    bits_lsb  = "".join(f"{b:08b}"[::-1] for b in data)
    return {
        "byte_length": len(data),
        "bit_length":  len(data) * 8,
        "hex":         hex_str,
        "base64":      b64_str,
        "bits":        bits_str,
        "bits_lsb_first": bits_lsb,
        "output": {
            "hex":    hex_str,
            "base64": b64_str,
            "bits":   bits_str,
            "utf8":   data.decode("utf-8", errors="replace"),
        }.get(output_encoding, hex_str),
    }


# ── Grain-128AEAD: NIST Core Input m₀ preview ────────────────────────────────

def _grain_encode_length(n: int) -> bytes:
    """
    Grain-128AEADv2 length encoding:
    bytes needed: ceil(log2(n+1)/7) using 7-bit groups with continuation bit,
    but the reference implementation uses a simpler 4-byte big-endian for clarity.
    We match the visual display expected by the frontend.
    """
    return struct.pack(">I", n)  # 4-byte big-endian


def build_core_input_preview(plaintext: bytes, ad: bytes) -> dict:
    encoded_ad_len = _grain_encode_length(len(ad))
    m0 = encoded_ad_len + ad + plaintext + b"\x80"
    return {
        "associated_data_length_bytes": len(ad),
        "plaintext_length_bytes":       len(plaintext),
        "encoded_ad_length":            normalized(encoded_ad_len),
        "associated_data":              normalized(ad),
        "plaintext":                    normalized(plaintext),
        "padding_byte":                 normalized(b"\x80"),
        "core_input_m0":                normalized(m0),
        "mask_for_encrypted_region_bits": "",
        "mask_for_encrypted_region_length_bits": 0,
    }


# ══════════════════════════════════════════════════════════════════════════════
# FastAPI app
# ══════════════════════════════════════════════════════════════════════════════

# Load hash plugins dynamically
HashRegistry.load_plugins(str(BASE_DIR / 'hash_plugins'))

app = FastAPI(
    title="KriptoFlow API",
    description="Grain-128AEAD · GIFT-COFB · ISAP · ASCON · XOODYAK · HC-128 · HC-256 · RC4 · Rabbit · Salsa20 · ChaCha20-Poly1305 · Hashes",
    version="2.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Generic encrypt/decrypt handlers ─────────────────────────────────────────

def handle_encrypt(algo_id: str, req: EncryptRequest) -> dict:
    algo = ALGOS.get(algo_id)
    if algo is None:
        raise HTTPException(404, f"Bilinmeyen algoritma: {algo_id}")

    try:
        key       = decode_input(req.key)
        nonce     = decode_input(req.nonce)
        plaintext = decode_input(req.plaintext)
        ad        = decode_input(req.associated_data)
    except Exception as e:
        raise HTTPException(422, f"Girdi çözümleme hatası: {e}")

    # Validate sizes (key_bytes=0 or nonce_bytes=0 means variable/absent — skip check)
    if algo.key_bytes > 0 and len(key) != algo.key_bytes:
        raise HTTPException(422, f"Key {algo.key_bytes*8}-bit olmalı ({len(key)*8}-bit alındı)")
    if algo.nonce_bytes > 0 and len(nonce) != algo.nonce_bytes:
        raise HTTPException(422, f"Nonce {algo.nonce_bytes*8}-bit olmalı ({len(nonce)*8}-bit alındı)")

    try:
        ciphertext, tag = algo.encrypt(key, nonce, plaintext, ad)
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))

    enc = req.output_encoding
    resp = {
        "implemented": True,
        "message": f"{algo.display_name} — gerçek implementasyon ({getattr(algo, 'backend', 'DLL')})",
        "ciphertext":             normalized(ciphertext, enc),
        "tag":                    normalized(tag, enc),
        "nist_ciphertext_with_tag": normalized(ciphertext + tag, enc),
        "core_input_preview": None,
        "normalized_inputs": None,
    }

    if req.include_core_input_preview and algo_id == "grain128aead":
        resp["core_input_preview"] = build_core_input_preview(plaintext, ad)

    return resp


def handle_salsa20(req: Salsa20Request, operation: str) -> dict:
    try:
        key   = decode_input(req.key)
        nonce = decode_input(req.nonce)
        data  = decode_input(req.data)
    except Exception as e:
        raise HTTPException(422, f"Girdi çözümleme hatası: {e}")

    try:
        result = SALSA20.crypt(key, nonce, data, req.stream_index)
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))

    payload_key = "ciphertext" if operation == "encrypt" else "plaintext"
    response = {
        "implemented":  True,
        "message":      "Salsa20 — gerçek implementasyon (DLL)",
        "stream_index": req.stream_index,
        payload_key:    normalized(result, req.output_encoding),
        "normalized_inputs": None,
    }
    if req.include_normalized_inputs:
        response["normalized_inputs"] = {
            "key":   normalized(key),
            "nonce": normalized(nonce),
            "data":  normalized(data),
        }
    return response


def handle_chacha20poly1305_encrypt(req: EncryptRequest) -> dict:
    if not CHACHA20POLY1305_AVAILABLE:
        raise HTTPException(500, f"ChaCha20-Poly1305 kullanılamıyor: {CHACHA20POLY1305_IMPORT_ERROR}")

    try:
        key       = decode_input(req.key)
        nonce     = decode_input(req.nonce)
        plaintext = decode_input(req.plaintext)
        ad        = decode_input(req.associated_data)
    except Exception as e:
        raise HTTPException(422, f"Girdi çözümleme hatası: {e}")

    try:
        result = chacha20poly1305_encrypt_impl(
            key=key, nonce=nonce, plaintext=plaintext, aad=ad,
            key_encoding="raw", nonce_encoding="raw",
            plaintext_encoding="raw", aad_encoding="raw",
            output_encoding="bytes",
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))

    ciphertext = result["ciphertext"]
    tag        = result["tag"]
    enc        = req.output_encoding
    response   = {
        "implemented":              True,
        "message":                  "ChaCha20-Poly1305 — gerçek implementasyon (Python)",
        "ciphertext":               normalized(ciphertext, enc),
        "tag":                      normalized(tag, enc),
        "nist_ciphertext_with_tag": normalized(ciphertext + tag, enc),
        "core_input_preview":       None,
        "normalized_inputs":        None,
    }
    if req.include_normalized_inputs:
        response["normalized_inputs"] = {
            "key": normalized(key), "nonce": normalized(nonce),
            "plaintext": normalized(plaintext), "associated_data": normalized(ad),
        }
    return response


def handle_chacha20poly1305_decrypt(req: DecryptRequest) -> dict:
    if not CHACHA20POLY1305_AVAILABLE:
        raise HTTPException(500, f"ChaCha20-Poly1305 kullanılamıyor: {CHACHA20POLY1305_IMPORT_ERROR}")

    try:
        key        = decode_input(req.key)
        nonce      = decode_input(req.nonce)
        ciphertext = decode_input(req.ciphertext)
        tag        = decode_input(req.tag)
        ad         = decode_input(req.associated_data)
    except Exception as e:
        raise HTTPException(422, f"Girdi çözümleme hatası: {e}")

    try:
        plaintext = chacha20poly1305_decrypt_impl(
            key=key, nonce=nonce, ciphertext=ciphertext, tag=tag, aad=ad,
            key_encoding="raw", nonce_encoding="raw",
            ciphertext_encoding="raw", tag_encoding="raw", aad_encoding="raw",
            output_encoding="bytes",
        )
        valid = True
        msg   = "Doğrulama başarılı — plaintext kurtarıldı"
    except ValueError as e:
        plaintext = b""
        valid     = False
        msg       = str(e)
    except Exception as e:
        raise HTTPException(500, str(e))

    enc      = req.output_encoding
    response = {
        "implemented":        True,
        "message":            msg,
        "valid":              valid,
        "plaintext":          normalized(plaintext, enc),
        "core_input_preview": None,
        "normalized_inputs":  None,
    }
    if req.include_normalized_inputs:
        response["normalized_inputs"] = {
            "key": normalized(key), "nonce": normalized(nonce),
            "ciphertext": normalized(ciphertext), "tag": normalized(tag),
            "associated_data": normalized(ad),
        }
    return response


def handle_decrypt(algo_id: str, req: DecryptRequest) -> dict:
    algo = ALGOS.get(algo_id)
    if algo is None:
        raise HTTPException(404, f"Bilinmeyen algoritma: {algo_id}")

    try:
        key        = decode_input(req.key)
        nonce      = decode_input(req.nonce)
        ciphertext = decode_input(req.ciphertext)
        tag        = decode_input(req.tag)
        ad         = decode_input(req.associated_data)
    except Exception as e:
        raise HTTPException(422, f"Girdi çözümleme hatası: {e}")

    if algo.key_bytes > 0 and len(key) != algo.key_bytes:
        raise HTTPException(422, f"Key {algo.key_bytes*8}-bit olmalı")
    if algo.nonce_bytes > 0 and len(nonce) != algo.nonce_bytes:
        raise HTTPException(422, f"Nonce {algo.nonce_bytes*8}-bit olmalı")
    if algo.tag_bytes > 0 and len(tag) != algo.tag_bytes:
        raise HTTPException(422, f"Tag {algo.tag_bytes*8}-bit olmalı ({len(tag)*8}-bit alındı)")

    try:
        plaintext = algo.decrypt(key, nonce, ciphertext, tag, ad)
        valid = True
        msg   = "Doğrulama başarılı — plaintext kurtarıldı"
    except ValueError as e:
        plaintext = b""
        valid = False
        msg   = str(e)
    except RuntimeError as e:
        raise HTTPException(500, str(e))

    enc = req.output_encoding
    return {
        "implemented": True,
        "message":   msg,
        "valid":     valid,
        "plaintext": normalized(plaintext, enc),
        "core_input_preview": None,
        "normalized_inputs":  None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════════════

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
def health():
    algorithms = {
        k: {"available": v.available, "name": v.display_name}
        for k, v in ALGOS.items()
    }
    algorithms["salsa20"]          = {"available": SALSA20.available,           "name": "Salsa20"}
    algorithms["chacha20poly1305"] = {"available": CHACHA20POLY1305_AVAILABLE,  "name": "ChaCha20-Poly1305"}
    return {"status": "ok", "algorithms": algorithms}


# ── Grain-128 AEAD ────────────────────────────────────────────────────────────

@app.post("/api/v1/grain128aeadv2/encrypt")
def grain_encrypt(req: EncryptRequest):
    return handle_encrypt("grain128aead", req)


@app.post("/api/v1/grain128aeadv2/decrypt")
def grain_decrypt(req: DecryptRequest):
    return handle_decrypt("grain128aead", req)


@app.get("/api/v1/grain128aeadv2/parameters")
def grain_parameters():
    return {
        "algorithm":       "Grain-128AEADv2",
        "key_bits":        128,
        "nonce_bits":      96,
        "tag_bits":        64,
        "plaintext":       "variable",
        "associated_data": "variable",
        "nist_core_input": "Encode(|AD|) || AD || PT || 0x80",
        "nonce_rule":      "Her şifreleme işlemi için benzersiz olmalı",
    }


# ── GIFT-COFB ─────────────────────────────────────────────────────────────────

@app.post("/api/v1/gift-cofb/encrypt")
def gift_encrypt(req: EncryptRequest):
    return handle_encrypt("gift-cofb", req)


@app.post("/api/v1/gift-cofb/decrypt")
def gift_decrypt(req: DecryptRequest):
    return handle_decrypt("gift-cofb", req)


@app.get("/api/v1/gift-cofb/parameters")
def gift_parameters():
    return {
        "algorithm":       "GIFT-COFB",
        "key_bits":        128,
        "nonce_bits":      128,
        "tag_bits":        128,
        "plaintext":       "variable",
        "associated_data": "variable",
    }


# ── ISAP ──────────────────────────────────────────────────────────────────────

@app.post("/api/v1/isap/encrypt")
def isap_encrypt(req: EncryptRequest):
    return handle_encrypt("isap", req)


@app.post("/api/v1/isap/decrypt")
def isap_decrypt(req: DecryptRequest):
    return handle_decrypt("isap", req)


@app.get("/api/v1/isap/parameters")
def isap_parameters():
    return {
        "algorithm":       "ISAP",
        "key_bits":        128,
        "nonce_bits":      128,
        "tag_bits":        128,
        "plaintext":       "variable",
        "associated_data": "variable",
    }


# ── ASCON ─────────────────────────────────────────────────────────────────────

@app.post("/api/v1/ascon/encrypt")
def ascon_encrypt(req: EncryptRequest):
    return handle_encrypt("ascon", req)


@app.post("/api/v1/ascon/decrypt")
def ascon_decrypt(req: DecryptRequest):
    return handle_decrypt("ascon", req)


@app.get("/api/v1/ascon/parameters")
def ascon_parameters():
    return {
        "algorithm":       "ASCON",
        "key_bits":        128,
        "nonce_bits":      128,
        "tag_bits":        128,
        "plaintext":       "variable",
        "associated_data": "variable",
    }


# ── XOODYAK ───────────────────────────────────────────────────────────────────

@app.post("/api/v1/xoodyak/encrypt")
def xoodyak_encrypt(req: EncryptRequest):
    return handle_encrypt("xoodyak", req)


@app.post("/api/v1/xoodyak/decrypt")
def xoodyak_decrypt(req: DecryptRequest):
    return handle_decrypt("xoodyak", req)


@app.get("/api/v1/xoodyak/parameters")
def xoodyak_parameters():
    return {
        "algorithm":       "XOODYAK",
        "key_bits":        128,
        "nonce_bits":      128,
        "tag_bits":        128,
        "plaintext":       "variable",
        "associated_data": "variable",
    }


# ── HC-128 ───────────────────────────────────────────────────────────────────

@app.post("/api/v1/hc-128/encrypt")
def hc128_encrypt(req: EncryptRequest):
    return handle_encrypt("hc-128", req)


@app.post("/api/v1/hc-128/decrypt")
def hc128_decrypt(req: DecryptRequest):
    return handle_decrypt("hc-128", req)


@app.get("/api/v1/hc-128/parameters")
def hc128_parameters():
    return {
        "algorithm":       "HC-128",
        "key_bits":        128,
        "nonce_bits":      128,
        "tag_bits":        0,
        "plaintext":       "variable",
        "associated_data": "none",
        "note":            "Stream cipher — şifreleme ve çözme aynı işlem (keystream XOR)",
    }


# ── HC-256 ───────────────────────────────────────────────────────────────────

@app.post("/api/v1/hc-256/encrypt")
def hc256_encrypt(req: EncryptRequest):
    return handle_encrypt("hc-256", req)


@app.post("/api/v1/hc-256/decrypt")
def hc256_decrypt(req: DecryptRequest):
    return handle_decrypt("hc-256", req)


@app.get("/api/v1/hc-256/parameters")
def hc256_parameters():
    return {
        "algorithm":       "HC-256",
        "key_bits":        256,
        "nonce_bits":      256,
        "tag_bits":        0,
        "plaintext":       "variable",
        "associated_data": "none",
        "note":            "Stream cipher — şifreleme ve çözme aynı işlem (keystream XOR)",
    }


# ── RC4 ──────────────────────────────────────────────────────────────────────

@app.post("/api/v1/rc4/encrypt")
def rc4_encrypt(req: EncryptRequest):
    return handle_encrypt("rc4", req)


@app.post("/api/v1/rc4/decrypt")
def rc4_decrypt(req: DecryptRequest):
    return handle_decrypt("rc4", req)


@app.get("/api/v1/rc4/parameters")
def rc4_parameters():
    return {
        "algorithm":       "RC4",
        "key_bits":        "variable (8–2048)",
        "nonce_bits":      0,
        "tag_bits":        0,
        "plaintext":       "variable",
        "associated_data": "none",
        "note":            "Stream cipher — IV kullanmaz, şifreleme ve çözme aynı işlem (keystream XOR)",
    }


# ── Rabbit ────────────────────────────────────────────────────────────────────

@app.post("/api/v1/rabbit/encrypt")
def rabbit_encrypt(req: EncryptRequest):
    return handle_encrypt("rabbit", req)


@app.post("/api/v1/rabbit/decrypt")
def rabbit_decrypt(req: DecryptRequest):
    return handle_decrypt("rabbit", req)


@app.get("/api/v1/rabbit/parameters")
def rabbit_parameters():
    return {
        "algorithm":       "Rabbit",
        "key_bits":        128,
        "nonce_bits":      64,
        "tag_bits":        0,
        "plaintext":       "variable",
        "associated_data": "none",
        "note":            "Stream cipher — şifreleme ve çözme aynı işlem (keystream XOR)",
    }


# ── Salsa20 ───────────────────────────────────────────────────────────────────

@app.post("/api/v1/salsa20/encrypt")
def salsa20_encrypt(req: EncryptRequest):
    salsa_req = Salsa20Request(
        key=req.key,
        nonce=req.nonce,
        data=req.plaintext,
        output_encoding=req.output_encoding,
        include_normalized_inputs=req.include_normalized_inputs,
    )
    return handle_salsa20(salsa_req, "encrypt")


@app.post("/api/v1/salsa20/decrypt")
def salsa20_decrypt(req: DecryptRequest):
    salsa_req = Salsa20Request(
        key=req.key,
        nonce=req.nonce,
        data=req.ciphertext,
        output_encoding=req.output_encoding,
        include_normalized_inputs=req.include_normalized_inputs,
    )
    return handle_salsa20(salsa_req, "decrypt")


@app.get("/api/v1/salsa20/parameters")
def salsa20_parameters():
    return {
        "algorithm":           "Salsa20",
        "key_bits":            256,
        "supported_key_bits":  [128, 256],
        "nonce_bits":          64,
        "tag_bits":            0,
        "plaintext":           "variable",
        "associated_data":     "kullanılmaz",
        "stream_index_bits":   32,
        "nonce_rule":          "Aynı key altında her şifreleme için benzersiz olmalı",
    }


# ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

@app.post("/api/v1/chacha20poly1305/encrypt")
def chacha20poly1305_encrypt(req: EncryptRequest):
    return handle_chacha20poly1305_encrypt(req)


@app.post("/api/v1/chacha20poly1305/decrypt")
def chacha20poly1305_decrypt(req: DecryptRequest):
    return handle_chacha20poly1305_decrypt(req)


@app.get("/api/v1/chacha20poly1305/parameters")
def chacha20poly1305_parameters():
    return {
        "algorithm":       "ChaCha20-Poly1305",
        "key_bits":        256,
        "nonce_bits":      96,
        "tag_bits":        128,
        "plaintext":       "variable",
        "associated_data": "variable",
        "nonce_rule":      "Her şifreleme işlemi için benzersiz olmalı",
    }


# ── Cryptography Hash Functions ───────────────────────────────────────────────

@app.get("/api/v1/hash/algorithms")
def get_hash_algorithms():
    return {
        algo_id: {
            "name": plugin.name,
            "description": plugin.description,
            "digest_size": plugin.digest_size
        }
        for algo_id, plugin in HashRegistry.get_all().items()
    }

@app.post("/api/v1/hash/compute")
def compute_hash(req: HashRequest):
    plugin = HashRegistry.get(req.algorithm_id)
    if not plugin:
        raise HTTPException(404, f"Hash algoritması bulunamadı: {req.algorithm_id}")
        
    try:
        data_bytes = decode_input(req.data)
        hash_bytes = plugin.compute_hash(data_bytes)
        
        return {
            "algorithm": plugin.name,
            "digest_size": plugin.digest_size,
            "hash": normalized(hash_bytes, req.output_encoding)
        }
    except Exception as e:
        raise HTTPException(422, f"Hash hesaplama hatası: {e}")


# ── Generic endpoint (tüm algoritmalar tek yoldan) ────────────────────────────

@app.post("/api/v1/{algo_id}/encrypt")
def generic_encrypt(algo_id: str, req: EncryptRequest):
    if algo_id in ("chacha20poly1305", "chacha20"):
        return handle_chacha20poly1305_encrypt(req)
    if algo_id not in ALGOS:
        raise HTTPException(404, f"Algoritma bulunamadı: {algo_id}")
    return handle_encrypt(algo_id, req)


@app.post("/api/v1/{algo_id}/decrypt")
def generic_decrypt(algo_id: str, req: DecryptRequest):
    if algo_id in ("chacha20poly1305", "chacha20"):
        return handle_chacha20poly1305_decrypt(req)
    if algo_id not in ALGOS:
        raise HTTPException(404, f"Algoritma bulunamadı: {algo_id}")
    return handle_decrypt(algo_id, req)


# ══════════════════════════════════════════════════════════════════════════════
# CLI helpers — Salsa20 ve ChaCha20-Poly1305 terminal arayüzleri
# ══════════════════════════════════════════════════════════════════════════════

def _prompt_choice(prompt: str, valid: set[str]) -> str:
    while True:
        value = input(prompt).strip().lower()
        if value in valid:
            return value
        print(f"Geçerli seçenekler: {', '.join(sorted(valid))}")


# ── Salsa20 CLI ───────────────────────────────────────────────────────────────

def _run_salsa20_cli_operation(*, mode, key_hex, nonce_hex, data_value, input_encoding, output_encoding, stream_index) -> int:
    key    = decode_input(EncodedValue(value=key_hex,    encoding="hex"))
    nonce  = decode_input(EncodedValue(value=nonce_hex,  encoding="hex"))
    data   = decode_input(EncodedValue(value=data_value, encoding=input_encoding))
    result = SALSA20.crypt(key, nonce, data, stream_index)
    rendered = normalized(result, output_encoding)
    utf8_preview = result.decode("utf-8", errors="backslashreplace").encode("unicode_escape").decode("ascii")
    print(f"\nİşlem       : {mode}")
    print(f"Key bytes   : {len(key)}")
    print(f"Nonce bytes : {len(nonce)}")
    print(f"Input bytes : {len(data)}")
    print(f"Offset      : {stream_index}")
    print(f"Çıktı ({output_encoding})\n" + "-" * 50)
    print(rendered["output"])
    print("-" * 50)
    print(f"Hex    : {rendered['hex']}")
    print(f"Base64 : {rendered['base64']}")
    print(f"UTF-8  : {utf8_preview}")
    return 0


def _run_salsa20_cli_interactive() -> int:
    print("Salsa20 Terminal Arayüzü\n" + "=" * 50)
    mode             = _prompt_choice("İşlem [encrypt/decrypt]: ", {"encrypt", "decrypt"})
    input_encoding   = _prompt_choice("Girdi kodlaması [utf8/hex/base64/bits]: ", {"utf8", "hex", "base64", "bits"})
    output_encoding  = _prompt_choice("Çıktı kodlaması [hex/utf8/base64/bits]: ", {"hex", "utf8", "base64", "bits"})
    key_hex          = input("Key (hex, 16 veya 32 byte): ").strip()
    nonce_hex        = input("Nonce (hex, 8 byte): ").strip()
    data_value       = input("Veri: ").strip()
    stream_index_raw = input("Stream index (varsayılan 0): ").strip() or "0"
    return _run_salsa20_cli_operation(
        mode=mode, key_hex=key_hex, nonce_hex=nonce_hex, data_value=data_value,
        input_encoding=input_encoding, output_encoding=output_encoding,
        stream_index=int(stream_index_raw),
    )


def run_salsa20_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Salsa20 DLL terminal arayüzü")
    parser.add_argument("--mode",         choices=["encrypt", "decrypt"])
    parser.add_argument("--key",          help="Hex key (16 veya 32 byte)")
    parser.add_argument("--nonce",        help="Hex nonce (8 byte)")
    parser.add_argument("--data",         help="İşlenecek veri")
    parser.add_argument("--input",        choices=["utf8", "hex", "base64", "bits"], default="utf8")
    parser.add_argument("--output",       choices=["hex", "utf8", "base64", "bits"],  default="hex")
    parser.add_argument("--stream-index", type=int, default=0)
    parser.add_argument("--interactive",  action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.interactive or not all([args.mode, args.key, args.nonce, args.data is not None]):
            return _run_salsa20_cli_interactive()
        return _run_salsa20_cli_operation(
            mode=args.mode, key_hex=args.key, nonce_hex=args.nonce,
            data_value=args.data, input_encoding=args.input,
            output_encoding=args.output, stream_index=args.stream_index,
        )
    except Exception as exc:
        print(f"Hata: {exc}")
        return 1


# ── ChaCha20-Poly1305 CLI ─────────────────────────────────────────────────────

def _run_chacha20poly1305_cli_encrypt(*, key_hex, nonce_hex, plaintext_value, aad_value, input_encoding, aad_encoding, output_encoding) -> int:
    key       = decode_input(EncodedValue(value=key_hex,          encoding="hex"))
    nonce     = decode_input(EncodedValue(value=nonce_hex,         encoding="hex"))
    plaintext = decode_input(EncodedValue(value=plaintext_value,   encoding=input_encoding))
    aad       = decode_input(EncodedValue(value=aad_value,         encoding=aad_encoding))
    req    = EncryptRequest(
        key=EncodedValue(value=key_hex, encoding="hex"),
        nonce=EncodedValue(value=nonce_hex, encoding="hex"),
        plaintext=EncodedValue(value=plaintext_value, encoding=input_encoding),
        associated_data=EncodedValue(value=aad_value, encoding=aad_encoding),
        output_encoding=output_encoding,
    )
    result = handle_chacha20poly1305_encrypt(req)
    print(f"\nİşlem       : encrypt")
    print(f"Key bytes   : {len(key)}  |  Nonce bytes : {len(nonce)}")
    print(f"PT bytes    : {len(plaintext)}  |  AAD bytes   : {len(aad)}")
    print(f"Çıktı ({output_encoding})\n" + "-" * 50)
    print(f"Ciphertext  : {result['ciphertext']['output']}")
    print(f"Tag         : {result['tag']['output']}")
    print(f"CT || Tag   : {result['nist_ciphertext_with_tag']['output']}")
    print("-" * 50)
    return 0


def _run_chacha20poly1305_cli_decrypt(*, key_hex, nonce_hex, ciphertext_value, tag_value, aad_value, input_encoding, tag_encoding, aad_encoding, output_encoding) -> int:
    key        = decode_input(EncodedValue(value=key_hex,            encoding="hex"))
    nonce      = decode_input(EncodedValue(value=nonce_hex,           encoding="hex"))
    ciphertext = decode_input(EncodedValue(value=ciphertext_value,    encoding=input_encoding))
    tag        = decode_input(EncodedValue(value=tag_value,           encoding=tag_encoding))
    aad        = decode_input(EncodedValue(value=aad_value,           encoding=aad_encoding))
    req    = DecryptRequest(
        key=EncodedValue(value=key_hex, encoding="hex"),
        nonce=EncodedValue(value=nonce_hex, encoding="hex"),
        ciphertext=EncodedValue(value=ciphertext_value, encoding=input_encoding),
        tag=EncodedValue(value=tag_value, encoding=tag_encoding),
        associated_data=EncodedValue(value=aad_value, encoding=aad_encoding),
        output_encoding=output_encoding,
    )
    result = handle_chacha20poly1305_decrypt(req)
    print(f"\nİşlem       : decrypt  |  Geçerli mi : {result['valid']}")
    print(f"Key bytes   : {len(key)}  |  Nonce bytes : {len(nonce)}")
    print(f"CT bytes    : {len(ciphertext)}  |  Tag bytes  : {len(tag)}  |  AAD bytes : {len(aad)}")
    print(f"Çıktı ({output_encoding})\n" + "-" * 50)
    print(result["plaintext"]["output"])
    print("-" * 50)
    print(f"Hex    : {result['plaintext']['hex']}")
    print(f"Base64 : {result['plaintext']['base64']}")
    return 0


def _run_chacha20poly1305_cli_interactive() -> int:
    print("ChaCha20-Poly1305 Terminal Arayüzü\n" + "=" * 50)
    mode            = _prompt_choice("İşlem [encrypt/decrypt]: ", {"encrypt", "decrypt"})
    input_encoding  = _prompt_choice("Veri kodlaması [utf8/hex/base64/bits]: ", {"utf8", "hex", "base64", "bits"})
    aad_encoding    = _prompt_choice("AAD kodlaması [utf8/hex/base64/bits]: ",  {"utf8", "hex", "base64", "bits"})
    output_encoding = _prompt_choice("Çıktı kodlaması [hex/utf8/base64/bits]: ", {"hex", "utf8", "base64", "bits"})
    key_hex         = input("Key (hex, 32 byte): ").strip()
    nonce_hex       = input("Nonce (hex, 12 byte): ").strip()
    if mode == "encrypt":
        plaintext_value = input("Plaintext: ").strip()
        aad_value       = input("AAD (boş olabilir): ").strip()
        return _run_chacha20poly1305_cli_encrypt(
            key_hex=key_hex, nonce_hex=nonce_hex, plaintext_value=plaintext_value,
            aad_value=aad_value, input_encoding=input_encoding,
            aad_encoding=aad_encoding, output_encoding=output_encoding,
        )
    ciphertext_value = input("Ciphertext: ").strip()
    tag_value        = input("Tag (hex): ").strip()
    aad_value        = input("AAD: ").strip()
    return _run_chacha20poly1305_cli_decrypt(
        key_hex=key_hex, nonce_hex=nonce_hex, ciphertext_value=ciphertext_value,
        tag_value=tag_value, aad_value=aad_value, input_encoding=input_encoding,
        tag_encoding="hex", aad_encoding=aad_encoding, output_encoding=output_encoding,
    )


def run_chacha20poly1305_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="ChaCha20-Poly1305 terminal arayüzü")
    parser.add_argument("--mode",        choices=["encrypt", "decrypt"])
    parser.add_argument("--key",         help="Hex key (32 byte)")
    parser.add_argument("--nonce",       help="Hex nonce (12 byte)")
    parser.add_argument("--data",        help="Plaintext (encrypt) veya ciphertext (decrypt)")
    parser.add_argument("--tag",         help="Decrypt için tag (hex)")
    parser.add_argument("--aad",         default="")
    parser.add_argument("--input",       choices=["utf8", "hex", "base64", "bits"], default="utf8")
    parser.add_argument("--aad-input",   choices=["utf8", "hex", "base64", "bits"], default="hex")
    parser.add_argument("--output",      choices=["hex", "utf8", "base64", "bits"],  default="hex")
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.interactive or not all([args.mode, args.key, args.nonce, args.data is not None]):
            return _run_chacha20poly1305_cli_interactive()
        if args.mode == "encrypt":
            return _run_chacha20poly1305_cli_encrypt(
                key_hex=args.key, nonce_hex=args.nonce, plaintext_value=args.data,
                aad_value=args.aad, input_encoding=args.input,
                aad_encoding=args.aad_input, output_encoding=args.output,
            )
        if not args.tag:
            print("Hata: decrypt için --tag gerekli")
            return 1
        return _run_chacha20poly1305_cli_decrypt(
            key_hex=args.key, nonce_hex=args.nonce, ciphertext_value=args.data,
            tag_value=args.tag, aad_value=args.aad, input_encoding=args.input,
            tag_encoding="hex", aad_encoding=args.aad_input, output_encoding=args.output,
        )
    except Exception as exc:
        print(f"Hata: {exc}")
        return 1


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    if len(sys.argv) > 1 and sys.argv[1] == "salsa20-cli":
        raise SystemExit(run_salsa20_cli(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "chacha20poly1305-cli":
        raise SystemExit(run_chacha20poly1305_cli(sys.argv[2:]))
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
