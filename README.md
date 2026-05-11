# KriptoFlow — Grup 4 (I/O) Katkısı: MD5 & SHA-1 Kriptografik Özet Fonksiyonları

Bu README, **yeni gelen kullanıcıların / diğer grupların** projeye eklenen değişiklikleri hızlıca görebilmesi için hazırlanmış bir özet ve test rehberidir.

> **Kısa özet:** Projeye **MD5** ve **SHA-1** kriptografik hash fonksiyonları, **hiçbir kütüphane kullanılmadan** (kendi saf-Python implementasyonu) eklendi. Eklenti (plugin) mimarisi sayesinde başka gruplar yeni hash fonksiyonlarını tek dosya bırakarak entegre edebilir.

---

## 1. Neler değişti?

### Backend (`backend/api/`)
| Dosya | Değişiklik |
|---|---|
| `hash_plugins/md5_plugin.py` | `hashlib` çıkarıldı → **RFC 1321'e göre sıfırdan MD5** (padding + 64 turluk sıkıştırma fonksiyonu). |
| `hash_plugins/sha1_plugin.py` | **YENİ** — FIPS 180-4 / RFC 3174'e göre sıfırdan **SHA-1** (80 tur). |
| `hash_plugins/sha256_plugin.py` | Sadece metadata (`block_size=64`, `rounds=64`) eklendi (hâlâ `hashlib` kullanıyor — istek dışıydı). |
| `hash_registry.py` | `HashPlugin` taban sınıfına opsiyonel `block_size` ve `rounds` metadata'sı eklendi (geriye dönük uyumlu). |
| `server.py` | `GET /api/v1/hash/algorithms` artık `block_size` ve `rounds` da döndürüyor. |

### Frontend (`frontend/src/`)
| Dosya | Değişiklik |
|---|---|
| `types/algorithms.ts` | `AlgorithmDef`'e `isHash`, `digestBits`, `blockBits`, `rounds` alanları. |
| `api/hashApi.ts` | Backend metadata'sından `"Hash · 128-bit özet · 512-bit blok · 64 tur"` açıklaması üretiliyor; `Cryptographic Hash Functions` kategorisi; md5/sha1/sha256 için ikon+renk. |
| `components/nodes/AlgorithmNode.tsx` | Hash algoritmaları için ayrı `HashNodeView`: `#` ikonu, `Digest / Block / tur / Key yok · IV yok` rozetleri, tek **Plaintext** girişi + **özet (digest)** çıkışı, `Girdi: N byte`, `<Algo> Özeti (HEX)` ve `Base64` alanları. |
| `components/sidebar/AlgorithmSelector.tsx` | Sidebar rozetleri hash için Digest/Block/tur/Key-yok şeklinde. |
| `hooks/useFlowStore.ts` | Hash dalı `algo.isHash` ile çalışıyor; girdi bayt uzunluğu hesaplanıp node'a yazılıyor. |
| `types/nodes.ts` | `AlgorithmNodeData`'ya `hashInputBytes` alanı. |

---

## 2. Çalıştırma

```bash
# 1) Backend (FastAPI / uvicorn) — http://127.0.0.1:8000
cd backend/api
pip install -r requirements.txt          # ilk sefer
python server.py

# 2) Frontend (Vite + React) — http://localhost:5173
cd frontend
npm install                              # ilk sefer
npm run dev
```

Tarayıcıda `http://localhost:5173/` (port doluysa Vite 5174/5180… der). Sağdaki **"Algoritmalar"** panelinde **CRYPTOGRAPHIC HASH FUNCTIONS** başlığı altında **MD5 / SHA-1 / SHA-256** görünür.

**Kullanım:** Algoritmayı canvas'a sürükle → bir **Plaintext Input** node'u ekle, metni yaz (boş özet için kutuyu boş bırak, *Padding* kapalı) → handle'lardan birbirine bağla → **▶ Run**. Node, `Digest / Block / tur` rozetleri, `Girdi: N byte` ve HEX + Base64 özet değerlerini gösterir.

---

## 3. API ile doğrudan test

```bash
# Mevcut hash algoritmaları + metadata
curl http://127.0.0.1:8000/api/v1/hash/algorithms

# Özet hesapla
curl -X POST http://127.0.0.1:8000/api/v1/hash/compute \
  -H "Content-Type: application/json" \
  -d '{"algorithm_id":"sha1","data":{"value":"abc","encoding":"utf8"},"output_encoding":"hex"}'
# → {"algorithm":"SHA-1","digest_size":20,"hash":{"hex":"a9993e36...d0d89d", ...}}
```

`encoding` değerleri: `utf8`, `hex`, `base64`, `bits`. `output_encoding`: `hex`, `base64`, `bits`, `utf8`.

---

## 4. Test vektörleri (RFC referans değerleriyle birebir uyumlu)

| Girdi (UTF-8) | MD5 (128-bit) | SHA-1 (160-bit) |
|---|---|---|
| *(boş, 0 byte)* | `d41d8cd98f00b204e9800998ecf8427e` | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `a` | `0cc175b9c0f1b6a831c399e269772661` | `86f7e437faa5a7fce15d1ddcb9eaeaea377667b8` |
| `abc` | `900150983cd24fb0d6963f7d28e17f72` | `a9993e364706816aba3e25717850c26c9cd0d89d` |
| `message digest` | `f96b697d7cb7938d525a2f31aaf161d0` | `c12252ceda8be8994d5fa0290a47231c1d16aae3` |
| `abcdefghijklmnopqrstuvwxyz` | `c3fcd3d76192e4007dfb496cca67e13b` | `32d10c7b8cf96570ca04ce37f2a19d84240d3a89` |
| `The quick brown fox jumps over the lazy dog` | `9e107d9d372bb6826bd81d3542a419d6` | `2fd4e1c67a2d28fced849ee1bb76e7391b93eb12` |
| `The quick brown fox jumps over the lazy cog` | `1055d3e698d289f2af8663725127bd4b` | `de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3` |
| `1234567890` ×8 (80 byte) | `57edf4a22be3c955ac49da2e2107b67a` | `50abf5706a150990a08b2c5ea40fa0e585554732` |
| `a` ×1.000.000 | `7707d6ae4e027c70eea2a935c2296f21` | `34aa973cd4c4daa4f61eeb2bdbad27316534016f` |

Base64 (boş girdi): MD5 → `1B2M2Y8AsgTpgAmY7PhCfg==`, SHA-1 → `2jmj7l5rSw0yVb/vlWAYkK/YBwk=`

> Not: `dog` → `cog` tek harf farkı özetin tamamen değişmesini (çığ etkisi) gösterir; uzun girdiler (80 byte, 1 MB) çok-bloklu padding'in doğruluğunu test eder.

### Hızlı self-test

```bash
cd backend/api
python -c "
import sys; sys.path.insert(0,'hash_plugins')
from md5_plugin import md5
from sha1_plugin import sha1
import hashlib
for t in [b'', b'abc', b'The quick brown fox jumps over the lazy dog', b'a'*1000000]:
    assert md5(t)  == hashlib.md5(t).digest()
    assert sha1(t) == hashlib.sha1(t).digest()
print('MD5 & SHA-1 implementasyonlari DOGRU.')
"
```

---

## 5. Başka bir grup yeni hash fonksiyonu nasıl ekler?

Eklenti mimarisi `backend/api/hash_registry.py` içindeki `HashPlugin` soyut sınıfına dayanır ve `hash_plugins/` klasörü otomatik taranır.

1. `backend/api/hash_plugins/` içine yeni bir dosya aç (örn. `sha256_pure_plugin.py`).
2. `HashPlugin`'den türeyen bir sınıf yaz ve şunları doldur:
   - `id` → benzersiz kimlik (örn. `"sha512"`)
   - `name` → ekranda görünecek ad (örn. `"SHA-512"`)
   - `description` → kısa açıklama
   - `digest_size` → özet uzunluğu (byte)
   - *(opsiyonel)* `block_size`, `rounds` → frontend'de rozet olarak gösterilir
   - `compute_hash(self, data: bytes) -> bytes` → asıl hesaplama
3. Backend'i yeniden başlat. Registry eklentiyi otomatik bulur (`[OK] Hash Plugin registered: ...`), frontend de `/api/v1/hash/algorithms`'tan çekip sidebar'a ekler. Ekstra kod gerekmez.

`md5_plugin.py` ve `sha1_plugin.py` doğrudan birer şablon olarak kullanılabilir.

---

*Bu dosya değişikliklerin gözden geçirilmesi/test edilmesi içindir; ana proje dokümantasyonu ile birleştirilebilir.*
