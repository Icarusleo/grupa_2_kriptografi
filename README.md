# KriptoFlow — Kriptografik Hash Fonksiyonları (Birleşik README)

Bu belge, **KriptoFlow** projesine farklı grupların eklediği kriptografik özet (hash) fonksiyonlarının ortak dokümantasyonudur. Her grup kendi algoritma ailesini, **hiçbir kütüphane kullanmadan (özellikle `hashlib` yok) saf Python ile** sıfırdan implemente etmiştir; algoritmalar projenin **modüler plugin (Strateji Deseni)** mimarisine entegre edilmiştir.



| Dal (branch) | Grup | Eklenen aile | Algoritmalar | Standart |
|---|---|---|---|---|
| `grup-4-sha-1-md5` | Grup 4 (I/O) | MD5, SHA-1 | MD5, SHA-1 | RFC 1321 / FIPS 180-4, RFC 3174 |
| *(A2 sürümü)* | Grup A2 | SHA-2 | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS 180-4 |
| `grup-7` | Grup 7 | SHA-3 + BLAKE2 | SHA3-224/256/384/512, SHAKE128, SHAKE256, BLAKE2b, BLAKE2s | FIPS 202, RFC 7693 |
| `feature/ripemd160` | — | RIPEMD-160 | RIPEMD-160 | RIPEMD-160 (Dobbertin–Bosselaers–Preneel) |
| `gost-hash-feature` | — | GOST / Streebog | GOST R 34.11-94, Streebog-256, Streebog-512 | RFC 5831, RFC 6986 (GOST R 34.11-2012) |
| `grup-3` | Grup 3 | *(henüz katkı yok)* | — | — |

---

## 1. Çalıştırma

```bash
# Backend (FastAPI / uvicorn) — http://127.0.0.1:8000  (Swagger: /docs)
cd backend/api
pip install -r requirements.txt          # ilk sefer
python server.py            # veya: uvicorn server:app --reload --port 8000

# Frontend (React + Vite) — http://localhost:5173
cd frontend
npm install                              # ilk sefer
npm run dev
```

Tarayıcıda sağdaki **"Algoritmalar"** panelinde **CRYPTOGRAPHIC HASH FUNCTIONS** başlığı altında, backend'de kayıtlı tüm hash algoritmaları otomatik listelenir (frontend listeyi `/api/v1/hash/algorithms`'tan dinamik çeker). Algoritmayı canvas'a sürükle → bir **Plaintext Input** node'una bağla → **▶ Run** → özet HEX + Base64 olarak gösterilir.

---

## 2. Hash API

```http
POST /api/v1/hash/compute
Content-Type: application/json

{ "algorithm_id": "sha256",
  "data": { "value": "abc", "encoding": "utf8" },
  "output_encoding": "hex" }
```

```bash
curl http://127.0.0.1:8000/api/v1/hash/algorithms         # kayıtlı algoritmalar + metadata
curl -X POST http://127.0.0.1:8000/api/v1/hash/compute \
  -H "Content-Type: application/json" \
  -d '{"algorithm_id":"sha1","data":{"value":"abc","encoding":"utf8"},"output_encoding":"hex"}'
```

`encoding`: `utf8` · `hex` · `base64` · `bits` (MSB-first).  `output_encoding`: `hex` · `base64` · `bits` · `utf8`.

---

## 3. "abc" için tüm aile — hızlı karşılaştırma

| Algoritma | `"abc"` özeti (hex) | Özet boyutu |
|---|---|---|
| MD5 | `900150983cd24fb0d6963f7d28e17f72` | 128-bit |
| SHA-1 | `a9993e364706816aba3e25717850c26c9cd0d89d` | 160-bit |
| RIPEMD-160 | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` | 160-bit |
| SHA-224 | `23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7` | 224-bit |
| SHA-256 | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | 256-bit |
| SHA-384 | `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7` | 384-bit |
| SHA-512 | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f` | 512-bit |
| SHA-512/224 | `4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa` | 224-bit |
| SHA-512/256 | `53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23` | 256-bit |
| SHA3-224 | `e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf` | 224-bit |
| SHA3-256 | `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532` | 256-bit |
| SHA3-384 | `ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25` | 384-bit |
| SHA3-512 | `b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0` | 512-bit |
| SHAKE128 (32 B) | `5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8` | değişken |
| SHAKE256 (64 B) | `483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4` | değişken |
| BLAKE2b (64 B) | `ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923` | 1–64 byte |
| BLAKE2s (32 B) | `508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982` | 1–32 byte |
| GOST R 34.11-94* | bkz. §8 (test mesajı `abc` değil) | 256-bit |
| Streebog-256 | bkz. §8 | 256-bit |
| Streebog-512 | bkz. §8 | 512-bit |

---

## 4. Grup 4 (I/O) — MD5 & SHA-1

**Dal:** `grup-4-sha-1-md5`  ·  **Çekirdek:** `hash_plugins/md5_plugin.py`, `hash_plugins/sha1_plugin.py` (saf Python, padding + sıkıştırma fonksiyonları sıfırdan)

| Algoritma | Özet | Blok | Tur | Yapı | Güvenlik | Standart |
|---|---|---|---|---|---|---|
| MD5 | 128-bit | 512-bit | 64 | Merkle–Damgård | ❌ kırılmış (collision pratik) | RFC 1321 |
| SHA-1 | 160-bit | 512-bit | 80 | Merkle–Damgård | ❌ collision'a karşı güvensiz | FIPS 180-4 / RFC 3174 |

**Frontend katkısı:** `AlgorithmDef`'e hash alanları (`isHash`, `digestBits`, `blockBits`, `rounds`), hash node'u (`HashNodeView` — `Digest / Block / tur / Key yok · IV yok` rozetleri, `Girdi: N byte`, `<Algo> Özeti (HEX)` + `Base64`), `useFlowStore` hash dalı. Backend: `HashPlugin`'e opsiyonel `block_size` / `rounds` metadata, `/api/v1/hash/algorithms` bu alanları döndürüyor.

**Test vektörleri** (`backend/api/test_hashes.py` — RFC 1321 / FIPS 180-4):

| Girdi (UTF-8) | MD5 | SHA-1 |
|---|---|---|
| *(boş, 0 byte)* | `d41d8cd98f00b204e9800998ecf8427e` | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `a` | `0cc175b9c0f1b6a831c399e269772661` | `86f7e437faa5a7fce15d1ddcb9eaeaea377667b8` |
| `abc` | `900150983cd24fb0d6963f7d28e17f72` | `a9993e364706816aba3e25717850c26c9cd0d89d` |
| `message digest` | `f96b697d7cb7938d525a2f31aaf161d0` | `c12252ceda8be8994d5fa0290a47231c1d16aae3` |
| `abcdefghijklmnopqrstuvwxyz` | `c3fcd3d76192e4007dfb496cca67e13b` | `32d10c7b8cf96570ca04ce37f2a19d84240d3a89` |
| `A..Z a..z 0..9` (62 byte) | `d174ab98d277d9f5a5611c2c9f419d9f` | `761c457bf73b14d27e9e9265c46f4b4dda11f940` |
| FIPS 56-byte örnek mesaj¹ | `8215ef0796a20bcaaae116d3876c664a` | `84983e441c3bd26ebaae4aa1f95129e5e54670f1` |
| `The quick brown fox jumps over the lazy dog` | `9e107d9d372bb6826bd81d3542a419d6` | `2fd4e1c67a2d28fced849ee1bb76e7391b93eb12` |
| `The quick brown fox jumps over the lazy cog` | `1055d3e698d289f2af8663725127bd4b` | `de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3` |
| `a` ×1.000.000 | `7707d6ae4e027c70eea2a935c2296f21` | `34aa973cd4c4daa4f61eeb2bdbad27316534016f` |

¹ `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` (56 byte) — çok-bloklu padding testi.

Çalıştırma: `cd backend/api && python test_hashes.py` → `TÜM TESTLER GEÇTİ (10 vektör × 2 algoritma).` (veya `pytest test_hashes.py`).

---

## 5. Grup A2 — SHA-2 Ailesi

**Çekirdek:** `sha2/sha2.py` (saf Python) — `SHA256Core` (SHA-224 / SHA-256, 32-bit kelime, 64 tur, 512-bit blok) ve `SHA512Core` (SHA-384 / SHA-512 / SHA-512-224 / SHA-512-256, 64-bit kelime, 80 tur, 1024-bit blok). Plugin katmanı: `hash_plugins/sha2_plugin.py`. `hashlib` kullanılmaz.

| Algoritma | Özet | Blok | Tur | Not |
|---|---|---|---|---|
| SHA-224 | 224-bit | 512-bit | 64 | SHA-256 çekirdeği, farklı IV, kısaltılır |
| SHA-256 | 256-bit | 512-bit | 64 | SHA-2'nin en yaygın üyesi |
| SHA-384 | 384-bit | 1024-bit | 80 | SHA-512 çekirdeği, farklı IV, kısaltılır |
| SHA-512 | 512-bit | 1024-bit | 80 | 64-bit kelimelerle çalışır |
| SHA-512/224 | 224-bit | 1024-bit | 80 | SHA-512 çekirdeği, ayrı IV (FIPS 180-4) |
| SHA-512/256 | 256-bit | 1024-bit | 80 | SHA-512 çekirdeği, ayrı IV (FIPS 180-4) |

**Test vektörleri** (NIST FIPS 180-4; M2 = 56-byte `abcdbcde…nopq`):

| Algoritma | `abc` | *(boş)* | FIPS 56-byte |
|---|---|---|---|
| SHA-224 | `23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7` | `d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f` | `75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525` |
| SHA-256 | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` |
| SHA-384 | `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7` | `38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b` | `3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b` |
| SHA-512 | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f` | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` | `204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445` |
| SHA-512/224 | `4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa` | `6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4` | — |
| SHA-512/256 | `53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23` | `c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a` | — |

---

## 6. Grup 7 — SHA-3 Ailesi & BLAKE2 (+ MD5 dokümantasyonu)

**Çekirdek:** `sha3_pure.py` ve ilgili BLAKE2 modülü (saf Python; `hashlib` yok). Frontend tarafında ayrı `HashNode.tsx` ve genişletilmiş `useFlowStore` / `types`. Sistem açılışında NIST KAT (Known Answer Test) vektörleriyle self-test çalıştırır.

> ⚠️ Bu dal, hash mimarisini yeniden tasarladığı için (`hash_registry.py` ve `frontend/src/api/hashApi.ts` kaldırılıyor) Grup 4 / A2 / RIPEMD / GOST katkılarıyla doğrudan birleşmiyor — hangi mimarinin (plugin registry mi, Grup 7 yaklaşımı mı) kalacağına karar verilmeli.

### SHA-3 (FIPS 202 — sponge yapısı, Keccak-f[1600], 24 round; suffix `0x06`)

| Fonksiyon | Çıktı | Rate | Capacity | Collision direnci |
|---|---|---|---|---|
| SHA3-224 | 28 byte | 1152 bit | 448 bit | 112 bit |
| SHA3-256 | 32 byte | 1088 bit | 512 bit | 128 bit |
| SHA3-384 | 48 byte | 832 bit | 768 bit | 192 bit |
| SHA3-512 | 64 byte | 576 bit | 1024 bit | 256 bit |
| SHAKE128 | değişken (d byte) | 1344 bit | 256 bit | ≤128 bit (suffix `0x1F`) |
| SHAKE256 | değişken (d byte) | 1088 bit | 512 bit | ≤256 bit (suffix `0x1F`) |

**Test vektörleri** (`abc`; SHAKE'ler örnek uzunlukla; ⊘ = boş girdi):

| Fonksiyon | Özet (hex) |
|---|---|
| SHA3-224 (`abc`) | `e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf` |
| SHA3-256 (`abc`) | `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532` |
| SHA3-384 (`abc`) | `ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25` |
| SHA3-384 (⊘) | `0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004` |
| SHA3-512 (`abc`) | `b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0` |
| SHA3-512 (⊘) | `a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26` |
| SHAKE128 (`abc`, 32 byte) | `5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8` |
| SHAKE256 (`abc`, 64 byte) | `483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4` |

### BLAKE2 (RFC 7693 — ARX / HAIFA; built-in key/salt/person; değişken çıktı)

| Algoritma | Hedef | Kelime | Blok | Tur | Max çıktı | Max key |
|---|---|---|---|---|---|---|
| BLAKE2b | 64-bit | 64 bit | 128 byte | 12 | 64 byte | 64 byte |
| BLAKE2s | 32-bit / IoT | 32 bit | 64 byte | 10 | 32 byte | 32 byte |

| Fonksiyon | Özet (hex) |
|---|---|
| BLAKE2b (`abc`, varsayılan 64 byte) | `ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923` |
| BLAKE2b (⊘, 64 byte) | `786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce` |
| BLAKE2s (`abc`, varsayılan 32 byte) | `508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982` |
| BLAKE2s (⊘, 32 byte) | `69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9` |

> Not: SHAKE çıktısı **prefix-stable**'dır (32 byte çıktı, 64 byte çıktının ilk 32 byte'ıdır); BLAKE2 değildir (digest_size parameter block'a girdiği için farklı boyutlar farklı domain gibi davranır).

---

## 7. RIPEMD-160

**Dal:** `feature/ripemd160`  ·  **Çekirdek:** `hash_plugins/ripemd160_core.py` + `hash_plugins/ripemd160_plugin.py` (saf Python, `hashlib` yok)

160-bit özet; Merkle–Damgård; iki paralel hat (her biri 5 tur × 16 adım = 80 adım), MD4/MD5 ailesinden esinli — Avrupa kökenli, açık tasarım.

**Test vektörleri** (kaynak: <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html>):

| Girdi | RIPEMD-160 (hex) |
|---|---|
| *(boş string)* | `9c1185a5c5e9fc54612808977ee8f548b2258d31` |
| `abc` | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` |
| `message digest` | `5d0689ef49d2fae572b881b123a85ffa21595f36` |
| `abcdefghijklmnopqrstuvwxyz` | `f71c27109c692c1b56bbdceb5b9d2865b3708dbc` |
| `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` (56 byte) | `12a053384a9c0c88e405a06c27dcf49ada62eb2b` |

---

## 8. GOST R 34.11-94 & Streebog (GOST R 34.11-2012)

**Dal:** `gost-hash-feature`  ·  **Çekirdek:** `hash_plugins/gost_hash_plugins.py` (+ `backend/api/gost/vendor/...` referans C kaynakları, doğrulama amaçlı). Sidebar/`hashApi.ts` için `sidebar_group` / `sidebar_icon` metadata eklenmiş; `backend/api/tests/test_gost_hash_integration.py` ve `test_rfc_public_vectors.py` ile doğrulanır.

| Algoritma | Özet | Standart |
|---|---|---|
| GOST R 34.11-94 | 256-bit | RFC 5831 (eski Rus standardı) |
| Streebog-256 | 256-bit | RFC 6986 (GOST R 34.11-2012) |
| Streebog-512 | 512-bit | RFC 6986 (GOST R 34.11-2012) |

**Test vektörleri** (`backend/api/tests/gost_test_readme.md`):

| Algoritma | Girdi | Özet (hex) | Kaynak |
|---|---|---|---|
| GOST R 34.11-94 | ASCII `This is message, length=32 bytes` (32 byte) | `b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa` | RFC 5831 §7.3.1 |
| GOST R 34.11-94 | ASCII `Suppose the original message has length = 50 bytes` (50 byte) | `471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208` | RFC 5831 §7.3.2 |
| Streebog-256 | boş mesaj | `3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb` | RFC 6986 §10.1 |
| Streebog-512 | boş mesaj | `8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a` | RFC 6986 §10.1 |
| Streebog-256 | ASCII `0123456789...0123` (63 byte, RFC "M1") | `9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500` | RFC 6986 §10.1 Örnek 1 |
| Streebog-512 | aynı 63-byte M1 | `1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48` | RFC 6986 §10.1 Örnek 1 |

---

## 9. Yeni bir hash fonksiyonu nasıl eklenir? (plugin mimarisi)

Plugin sistemi `backend/api/hash_registry.py` içindeki `HashPlugin` soyut sınıfına dayanır; `hash_plugins/` klasörü açılışta otomatik taranır.

1. `backend/api/hash_plugins/` içine yeni bir dosya aç (örn. `sha3_plugin.py`). Birden çok ilgili algoritma tek dosyada toplanabilir (bkz. SHA-2 çekirdeği) — registry her sınıfı ayrı kaydeder.
2. `HashPlugin`'den türeyen sınıf(lar) yaz:
   - `id` — benzersiz kimlik (örn. `"sha3-256"`)
   - `name` — ekranda görünecek ad
   - `description` — kısa açıklama
   - `digest_size` — özet uzunluğu (byte)
   - *(opsiyonel)* `block_size`, `rounds`, `sidebar_group`, `sidebar_icon` — frontend'de rozet/grup olarak gösterilir
   - `compute_hash(self, data: bytes) -> bytes` — asıl hesaplama (kütüphane kullanmadan)
3. *(önerilir)* Bir test dosyası ekle (`test_*.py`) ve resmi KAT vektörlerini koy.
4. Backend'i yeniden başlat → `[OK] Hash Plugin registered: ...` → frontend `/api/v1/hash/algorithms`'tan otomatik çeker. Ekstra UI kodu gerekmez.

`md5_plugin.py` / `sha1_plugin.py` (tek algoritma) ve `sha2_plugin.py` (çok algoritma + ortak çekirdek) birer şablon olarak kullanılabilir.

---

## 10. Kaynaklar

- **MD5** — RFC 1321 · **SHA-1 / SHA-2** — FIPS 180-4, RFC 3174 · **SHA-3 / SHAKE** — FIPS 202, NIST SP 800-185, Keccak referansı · **BLAKE2** — RFC 7693, <https://www.blake2.net> · **RIPEMD-160** — <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html> · **GOST / Streebog** — RFC 5831, RFC 6986
- NIST FIPS 180-4: <https://csrc.nist.gov/publications/detail/fips/180/4/final> · FIPS 202: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>

---

*Bu README birden çok grubun katkısını bir araya getirir. Dallar henüz `main`'e tam olarak birleştirilmedi; çakışan dosyalar ve mimari kararı için ekip içi koordinasyon gerekir.*
