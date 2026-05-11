# KriptoFlow — Kriptografi Algoritmaları Platformu

Grup A2 tarafından geliştirilen **KriptoFlow**, simetrik şifreleme ve hash fonksiyonlarını interaktif olarak test etmeye ve görselleştirmeye yarayan bir full-stack web uygulamasıdır.

---

## 🚀 Proje Yapısı

```
Kriptoquiz1-main/
├── backend/
│   └── api/
│       ├── server.py              # FastAPI ana sunucu
│       ├── hash_registry.py       # Modüler hash plugin sistemi
│       ├── hash_plugins/          # Hash algoritma plugin'leri
│       │   ├── sha2_plugin.py     # SHA-2 ailesi plugin'i
│       │   └── md5_plugin.py      # MD5 plugin'i
│       ├── sha2/
│       │   └── sha2.py            # SHA-2 saf Python implementasyonu
│       ├── rabbit/                # Rabbit stream cipher
│       ├── rc4/                   # RC4 stream cipher
│       ├── hc256/                 # HC-256 stream cipher
│       ├── chacha20poly1305_wrapper.py
│       ├── requirements.txt
│       └── *.dll                  # AEAD algoritma DLL'leri
└── frontend/
    ├── src/
    │   ├── api/                   # Backend API istemcileri
    │   ├── components/            # React bileşenleri
    │   ├── hooks/                 # Custom React hook'ları
    │   └── types/                 # TypeScript tip tanımları
    ├── package.json
    └── vite.config.ts
```

---

## ⚙️ Kurulum ve Çalıştırma

### Gereksinimler
- Python 3.11+
- Node.js 18+

### Backend (FastAPI)

```bash
cd backend/api
pip install -r requirements.txt
uvicorn server:app --reload --port 8000
```

API Swagger dokümantasyonu: **http://127.0.0.1:8000/docs**

### Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

Uygulama adresi: **http://localhost:5173**

---

## 🔐 Desteklenen Algoritmalar

### Simetrik Şifreleme (AEAD)
| Algoritma | Anahtar | Nonce | Etiket | Backend |
|-----------|---------|-------|--------|---------|
| Grain-128 AEAD | 128-bit | 96-bit | 64-bit | DLL |
| GIFT-COFB | 128-bit | 128-bit | 128-bit | DLL |
| ISAP | 128-bit | 128-bit | 128-bit | DLL |
| ASCON-80pq | 160-bit | 128-bit | 128-bit | DLL |
| XOODYAK | 128-bit | 128-bit | 128-bit | DLL |
| ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | Python |

### Stream Cipher
| Algoritma | Anahtar | IV | Backend |
|-----------|---------|-----|---------|
| Salsa20 | 128/256-bit | 64-bit | DLL |
| HC-128 | 128-bit | 128-bit | DLL |
| HC-256 | 256-bit | 256-bit | Python |
| RC4 | Değişken | — | Python |
| Rabbit | 128-bit | 64-bit | Python |

### Hash Fonksiyonları
| Algoritma | Özet Boyutu | Backend |
|-----------|-------------|---------|
| MD5 | 128-bit | Python |
| SHA-224 | 224-bit | Python |
| SHA-256 | 256-bit | Python |
| SHA-384 | 384-bit | Python |
| SHA-512 | 512-bit | Python |
| SHA-512/224 | 224-bit | Python |
| SHA-512/256 | 256-bit | Python |

---

## 🔑 SHA-2 Ailesi — Implementasyon Detayı

Bu projede SHA-2 ailesi algoritmaları **sıfırdan, saf Python** ile implement edilmiştir. Python'un standart `hashlib` kütüphanesi **kullanılmamıştır**.

### Implementasyon Mimarisi

```
hash_plugins/sha2_plugin.py   ← Plugin katmanı (HashRegistry entegrasyonu)
        │
        └─ sha2/sha2.py       ← Çekirdek implementasyon
               ├── SHA256Core   (SHA-224 ve SHA-256 için — 32-bit çekirdek)
               └── SHA512Core   (SHA-384, SHA-512, SHA-512/224, SHA-512/256 için — 64-bit çekirdek)
```

### Modüler Plugin Sistemi

SHA-2 algoritmaları, projenin **Strateji Deseni** tabanlı plugin mimarisine entegre edilmiştir. Her algoritma `HashPlugin` arayüzünü implement eden bağımsız bir sınıftır:

```python
# hash_plugins/sha2_plugin.py
from sha2 import sha2 as sha2_impl
from hash_registry import HashPlugin

class SHA256Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha256"

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha256(data)
```

Yeni bir hash algoritması eklemek için yalnızca `hash_plugins/` dizinine yeni bir plugin dosyası eklemek yeterlidir; `server.py` dosyasında herhangi bir değişiklik gerekmez.

---

## 🧪 SHA-2 Test Vektörleri

Aşağıdaki test vektörleri **NIST FIPS 180-4** standardından alınmıştır. Tüm girişler UTF-8 kodlamasında, çıkışlar hex formatındadır.

### SHA-224

| # | Giriş | Beklenen Hash (hex) |
|---|-------|---------------------|
| 1 | `abc` | `23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7` |
| 2 | *(boş string)* | `d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f` |
| 3 | `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` | `75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525` |

### SHA-256

| # | Giriş | Beklenen Hash (hex) |
|---|-------|---------------------|
| 1 | `abc` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| 2 | *(boş string)* | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 3 | `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |

### SHA-384

| # | Giriş | Beklenen Hash (hex) |
|---|-------|---------------------|
| 1 | `abc` | `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7` |
| 2 | *(boş string)* | `38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b` |
| 3 | `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` | `3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b` |

### SHA-512

| # | Giriş | Beklenen Hash (hex) |
|---|-------|---------------------|
| 1 | `abc` | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f` |
| 2 | *(boş string)* | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` |
| 3 | `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` | `204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445` |

### SHA-512/224

| # | Giriş | Beklenen Hash (hex) |
|---|-------|---------------------|
| 1 | `abc` | `4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa` |
| 2 | *(boş string)* | `6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4` |

### SHA-512/256

| # | Giriş | Beklenen Hash (hex) |
|---|-------|---------------------|
| 1 | `abc` | `53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23` |
| 2 | *(boş string)* | `c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a` |

---

## 🌐 API Kullanımı

### Hash Hesaplama

```http
POST /hash/compute
Content-Type: application/json

{
  "algorithm_id": "sha256",
  "data": {
    "value": "abc",
    "encoding": "utf8"
  },
  "output_encoding": "hex"
}
```

**Yanıt:**
```json
{
  "algorithm_id": "sha256",
  "hash": {
    "hex": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "byte_length": 32
  }
}
```

### Desteklenen Encoding'ler

| Encoding | Açıklama |
|----------|----------|
| `utf8` | Metin olarak |
| `hex` | Hexadecimal |
| `base64` | Base64 |
| `bits` | İkili (MSB-first) |

---

## 👥 Grup A2

Bu proje **Grup A2** tarafından Kriptografi dersi kapsamında geliştirilmiştir.

---

## 📚 Referanslar

- [NIST FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [NIST Lightweight Cryptography](https://csrc.nist.gov/projects/lightweight-cryptography)
- [RFC 7539 — ChaCha20 and Poly1305](https://datatracker.ietf.org/doc/html/rfc7539)
