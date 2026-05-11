# SHA3 Ailesi ve BLAKE2 Ailesi Kriptografik Hash Fonksiyonları

> **Grup 7**
> - Arzu Selda Avcı - 220202073
> - Ayaz Aktaş - 220202050
> - Yiğit Erdinç - 220202110

---

## İçindekiler

1. [Hash Fonksiyonu Nedir?](#hash-fonksiyonu-nedir)
2. [MD5](#1-md5)
3. [SHA-3 Ailesi](#2-sha-3-ailesi)
4. [BLAKE2 Ailesi](#3-blake2-ailesi)
5. [Karşılaştırma Tablosu](#karşılaştırma-tablosu)
6. [Kaynaklar](#kaynaklar)

---

## Hash Fonksiyonu Nedir?

Kriptografik hash fonksiyonu, herhangi uzunluktaki bir girdiyi (mesajı) sabit veya değişken uzunlukta bir çıktıya (hash / özet) dönüştüren tek yönlü matematiksel bir fonksiyondur. Güvenli bir hash fonksiyonu şu üç temel özelliği sağlamalıdır:

- **Preimage direnci:** Verilen bir `h` hash değeri için `H(m) = h` olacak şekilde `m` mesajını bulmak hesaplama açısından imkansız olmalıdır.
- **Second preimage direnci:** Verilen bir `m1` için `H(m1) = H(m2)` olacak şekilde farklı bir `m2` bulmak imkansız olmalıdır.
- **Collision direnci:** `H(m1) = H(m2)` olacak şekilde herhangi iki farklı `m1, m2` mesaj çifti bulmak imkansız olmalıdır.

Bu projede üç farklı hash algoritması ailesini inceliyoruz: tarihsel önemi olan ama artık kırılmış kabul edilen **MD5**, NIST tarafından standartlaştırılmış **SHA-3** ailesi ve modern, hızlı bir alternatif olan **BLAKE2** ailesi.

---

## 1. MD5

### Genel Bilgi

MD5 (Message Digest 5), 1991 yılında Ronald Rivest tarafından tasarlanmış, 128-bit özet üreten bir hash fonksiyonudur. **Merkle-Damgård** yapısı üzerine kuruludur ve uzun yıllar boyunca en yaygın kullanılan hash fonksiyonu olmuştur.

### Giriş

- **Mesaj:** Herhangi uzunlukta byte dizisi
- **Maksimum uzunluk:** 2^64 - 1 bit
- **Minimum uzunluk:** 0 bit (boş giriş geçerli)

### Çıkış

- **Sabit 128 bit = 16 byte = 32 hex karakter**

### İç Yapı

- Block boyutu: 512 bit (64 byte)
- 4 adet 32-bit başlangıç değeri (A, B, C, D)
- 64 round, 4 farklı doğrusal olmayan fonksiyon (F, G, H, I)
- Round sabitleri: `K[i] = floor(|sin(i+1)| × 2^32)` formülünden türetilir

### Güvenlik Durumu

> ⚠️ **MD5 kriptografik olarak kırılmıştır.**

MD5'te collision (çakışma) saldırıları pratik olarak mümkündür. 2004'te ilk pratik collision gösterilmiştir; günümüzde saniyeler içinde collision üretilebilir.

**Kullanılmaması gereken yerler:** Dijital imza, şifre saklama, sertifika doğrulama, güvenlik kritik tüm uygulamalar.

**Hâlâ kabul edilebilir kullanımları:** Kasıtsız veri bozulması tespiti (checksum), non-kriptografik fingerprint, eski sistemlerle uyumluluk.

### Örnek Kullanım

```python
import hashlib
hashlib.md5(b"Merhaba Dünya").hexdigest()
# '5cc4d3035f9e8a2dbf7a8f3a30c1b5c8'
```

---

## 2. SHA-3 Ailesi

### Genel Bilgi

SHA-3 (Secure Hash Algorithm 3), 2015'te NIST tarafından **FIPS 202** standardı ile yayınlanmıştır. Keccak yarışmasının kazanan algoritması olarak Bertoni, Daemen, Peeters ve Van Assche tarafından tasarlanmıştır.

SHA-3'ün önceki SHA ailelerinden temel farkı, **Merkle-Damgård yerine sponge construction** kullanmasıdır. Bu yapı, çekirdek olarak 1600-bit durum üzerinde çalışan **Keccak-f[1600] permütasyonunu** kullanır.

### Sponge Construction

Sponge yapısı iki fazdan oluşur:

1. **Absorb (Emme):** Mesaj `rate` boyutlu bloklara bölünür, her blok state'in ilk `rate` bitine XOR'lanır, ardından permütasyon uygulanır.
2. **Squeeze (Sıkma):** Çıktı state'in ilk `rate` bitinden okunur. Daha fazla çıktı gerekirse permütasyon tekrar uygulanır.

Her zaman `rate (r) + capacity (c) = 1600 bit` eşitliği geçerlidir. Capacity ne kadar büyükse güvenlik o kadar yüksek, ama rate küçüldüğü için performans o kadar düşüktür.

### Keccak-f[1600] Permütasyonu

24 round çalışır ve her round 5 adımdan oluşur:

- **θ (theta):** Sütun pariteleri hesaplanır, diffüzyon sağlar
- **ρ (rho):** Her lane farklı miktarda rotate edilir
- **π (pi):** Lane'lerin pozisyonları permüte edilir
- **χ (chi):** Tek doğrusal olmayan adım (AND + NOT + XOR)
- **ι (iota):** Round sabiti eklenir, simetriyi kırar

### SHA-3 Ailesinin Üyeleri

SHA-3 ailesi iki kategoriye ayrılır: **sabit çıktılı hash fonksiyonları** (SHA3-N) ve **genişletilebilir çıktı fonksiyonları** (SHAKE).

#### 2.1. SHA3-224

| Özellik | Değer |
|---------|-------|
| Giriş | Herhangi uzunlukta mesaj |
| Çıkış | **28 byte (224 bit) sabit** |
| Rate (r) | 1152 bit |
| Capacity (c) | 448 bit |
| Suffix | `0x06` |
| Collision direnci | 112 bit |
| Preimage direnci | 224 bit |

```python
hashlib.sha3_224(b"abc").hexdigest()
# 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'
```

#### 2.2. SHA3-256

| Özellik | Değer |
|---------|-------|
| Giriş | Herhangi uzunlukta mesaj |
| Çıkış | **32 byte (256 bit) sabit** |
| Rate (r) | 1088 bit |
| Capacity (c) | 512 bit |
| Suffix | `0x06` |
| Collision direnci | 128 bit |
| Preimage direnci | 256 bit |

```python
hashlib.sha3_256(b"abc").hexdigest()
# '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
```

En yaygın kullanılan SHA-3 varyantıdır.

#### 2.3. SHA3-384

| Özellik | Değer |
|---------|-------|
| Giriş | Herhangi uzunlukta mesaj |
| Çıkış | **48 byte (384 bit) sabit** |
| Rate (r) | 832 bit |
| Capacity (c) | 768 bit |
| Suffix | `0x06` |
| Collision direnci | 192 bit |
| Preimage direnci | 384 bit |

```python
hashlib.sha3_384(b"abc").hexdigest()
```

#### 2.4. SHA3-512

| Özellik | Değer |
|---------|-------|
| Giriş | Herhangi uzunlukta mesaj |
| Çıkış | **64 byte (512 bit) sabit** |
| Rate (r) | 576 bit |
| Capacity (c) | 1024 bit |
| Suffix | `0x06` |
| Collision direnci | 256 bit |
| Preimage direnci | 512 bit |

En yüksek güvenlik seviyesine sahip ama en yavaş varyanttır.

```python
hashlib.sha3_512(b"abc").hexdigest()
```

#### 2.5. SHAKE128 (Extendable-Output Function)

| Özellik | Değer |
|---------|-------|
| Giriş | Mesaj + **istenen çıktı uzunluğu (d)** |
| Çıkış | **Değişken uzunlukta (d byte)** |
| Rate (r) | 1344 bit |
| Capacity (c) | 256 bit |
| Suffix | `0x1F` |
| Genel güvenlik | 128 bit |

SHAKE'in özelliği, kullanıcının istediği uzunlukta çıktı üretebilmesidir. SHAKE128 ayrıca SHA-3 ailesinin **en hızlı** üyesidir (en yüksek rate).

```python
hashlib.shake_128(b"abc").hexdigest(32)  # 32 byte çıktı
hashlib.shake_128(b"abc").hexdigest(64)  # 64 byte çıktı
# İlk 32 byte aynıdır — SHAKE çıktıları prefix-stable'dır
```

#### 2.6. SHAKE256

| Özellik | Değer |
|---------|-------|
| Giriş | Mesaj + istenen çıktı uzunluğu (d) |
| Çıkış | Değişken uzunlukta (d byte) |
| Rate (r) | 1088 bit |
| Capacity (c) | 512 bit |
| Suffix | `0x1F` |
| Genel güvenlik | 256 bit |

SHAKE128'den daha güvenli ama daha yavaştır.

### SHA-3 Domain Separation

`0x06` (SHA-3) ve `0x1F` (SHAKE) suffix'leri farklı domain'ler oluşturur. Aynı mesaj farklı fonksiyonlara verildiğinde tamamen farklı sonuçlar üretir — bu kasıtlı bir tasarımdır.

### Güvenlik Durumu

✅ SHA-3 ailesi **kriptografik olarak güvenlidir** ve günümüzün en yüksek güvenlik standartlarını karşılar. Henüz pratik bir saldırı bulunmamıştır.

### KriptoFlow Projesinde SHA-3 Gerçekleşimi

Bu proje kapsamında SHA-3 algoritma ailesi, herhangi bir dış kütüphane (hashlib vb.) kullanılmadan, tamamen **NIST FIPS 202** standartlarına sadık kalınarak sıfırdan Python dili ile gerçeklenmiştir.

#### Uygulama Detayları
- **Keccak-f[1600] Permütasyonu:** 1600 bitlik durum matrisi üzerinde çalışan θ, ρ, π, χ ve ι adımları bit düzeyinde kodlanmıştır.
- **Sünger (Sponge) Yapısı:** Mesajın `rate` bloklarına bölünerek state'e XOR'landığı (Absorb) ve ardından özetin üretildiği (Squeeze) yapı standartlara uygun olarak kurulmuştur.
- **Dinamik Plugin Sistemi:** Hazırlanan algoritmalar birer "Plugin" olarak tasarlanmış ve backend sistemine dinamik olarak dahil edilmiştir. Bu sayede frontend arayüzü yeni eklenen algoritmaları otomatik olarak tanıyabilmektedir.

#### Doğrulama
Kodun doğruluğu, NIST tarafından sağlanan **Known Answer Tests (KAT)** vektörleri ile test edilmiştir. Proje başlatıldığında sistem, tüm SHA-3 varyantları (224, 256, 384, 512, SHAKE128, SHAKE256) için otomatik doğrulama testlerini (Self-Test) başarıyla tamamlar.

---

### KriptoFlow Projesinde BLAKE2 Gerçekleşimi

BLAKE2 algoritma ailesi (BLAKE2b ve BLAKE2s), **RFC 7693** standartlarına uygun olarak, herhangi bir dış kütüphane kullanılmadan tamamen Python ile gerçeklenmiştir.

#### Uygulama Detayları
- **BLAKE2b:** 64-bit sistemler için optimize edilmiş varyanttır. ARX (Addition-Rotation-XOR) yapısı ve G mixing fonksiyonu 64-bit lane'ler üzerinde gerçeklenmiştir.
- **BLAKE2s:** 32-bit sistemler için optimize edilmiştir. İşlemler 32-bit kelimeler üzerinde yürütülür.
- **Dinamik Plugin Sistemi:** Hazırlanan algoritmalar sisteme plugin olarak dahil edilmiş, frontend arayüzü ile tam entegrasyon sağlanmıştır.

#### Doğrulama
BLAKE2 implementasyonları, resmi test vektörleri (KAT) ile doğrulanmıştır. Sistem başlatıldığında otomatik doğrulama testlerini çalıştırarak güvenilirliği garanti eder.

---

## 3. BLAKE2 Ailesi

### Genel Bilgi

BLAKE2, 2012'de Aumasson, Neves, Wilcox-O'Hearn ve Winnerlein tarafından tasarlanmıştır. **RFC 7693** standardında tanımlıdır. BLAKE2, SHA-3 finalisti olan BLAKE'in geliştirilmiş, basitleştirilmiş ve hızlandırılmış versiyonudur.

BLAKE2'nin felsefesi: **"MD5 kadar hızlı, SHA-3 kadar güvenli."** Stream cipher olan **ChaCha20**'nin yapısından ilham alır.

### BLAKE2'nin Ayırt Edici Özellikleri

BLAKE2, diğer hash fonksiyonlarından önemli bir konuda ayrılır: **tek bir algoritmada birden fazla rol** oynayabilir. Parameter block yapısı sayesinde:

- **Hash** (normal mesaj özeti)
- **MAC** (anahtarlı mod, HMAC gerekmez)
- **KDF** (anahtar türetme)
- **PRF** (pseudo-random function)
- **Tree hash** (paralel hashleme)

rollerinin hepsi aynı algoritmada yapılır. Bu, BLAKE2'yi "İsviçre çakısı" benzeri bir araç yapar.

### G Mixing Fonksiyonu

BLAKE2'nin çekirdek operasyonu **G mixing fonksiyonudur**. Her round'da 8 kez çalıştırılır (4 sütun + 4 çapraz). Yapısı ARX (Addition-Rotation-XOR) operasyonlarına dayanır:

```
v[a] = v[a] + v[b] + x
v[d] = rotr(v[d] XOR v[a], R1)
v[c] = v[c] + v[d]
v[b] = rotr(v[b] XOR v[c], R2)
v[a] = v[a] + v[b] + y
v[d] = rotr(v[d] XOR v[a], R3)
v[c] = v[c] + v[d]
v[b] = rotr(v[b] XOR v[c], R4)
```

### BLAKE2 Ailesinin Üyeleri

#### 3.1. BLAKE2b

64-bit platformlar için optimize edilmiştir.

**Giriş Parametreleri:**

| Parametre | Aralık | Açıklama |
|-----------|--------|----------|
| **Mesaj (M)** | Herhangi uzunlukta | Hashlenecek veri |
| **Key** | 0-64 byte | İsteğe bağlı — MAC modu için |
| **Salt** | 0-16 byte | İsteğe bağlı — randomize hashing |
| **Person** | 0-16 byte | İsteğe bağlı — domain separation |
| **Digest size** | 1-64 byte | Çıktı uzunluğu (varsayılan 64) |

**İç Parametreler:**

- Word boyutu: 64 bit
- Block boyutu: 128 byte
- Round sayısı: 12
- IV: SHA-512 ile aynı
- Rotasyon offsetleri: (32, 24, 16, 63)

**Çıkış:**

- 1-64 byte arası, kullanıcının belirlediği uzunlukta

**Güvenlik:**

- Collision direnci: `digest_size / 2` bit (max 256 bit)
- Preimage direnci: `digest_size` bit (max 512 bit)

**Örnek:**

```python
# Varsayılan 64 byte çıktı
hashlib.blake2b(b"abc").hexdigest()

# 32 byte çıktı
hashlib.blake2b(b"abc", digest_size=32).hexdigest()

# Anahtarlı mod (MAC)
hashlib.blake2b(b"mesaj", key=b"gizli_anahtar").hexdigest()

# Tam parametreli kullanım
hashlib.blake2b(
    b"data",
    digest_size=32,
    key=b"secret",
    salt=b"unique_salt_16by",
    person=b"my_application"
).hexdigest()
```

#### 3.2. BLAKE2s

32-bit platformlar, IoT cihazları ve küçük sistemler için optimize edilmiştir.

**Giriş Parametreleri:**

| Parametre | Aralık | Açıklama |
|-----------|--------|----------|
| **Mesaj (M)** | Herhangi uzunlukta | Hashlenecek veri |
| **Key** | 0-32 byte | İsteğe bağlı — MAC modu için |
| **Salt** | 0-8 byte | İsteğe bağlı |
| **Person** | 0-8 byte | İsteğe bağlı |
| **Digest size** | 1-32 byte | Çıktı uzunluğu (varsayılan 32) |

**İç Parametreler:**

- Word boyutu: 32 bit
- Block boyutu: 64 byte
- Round sayısı: 10
- IV: SHA-256 ile aynı
- Rotasyon offsetleri: (16, 12, 8, 7)

**Çıkış:**

- 1-32 byte arası, kullanıcının belirlediği uzunlukta

**Güvenlik:**

- Collision direnci: `digest_size / 2` bit (max 128 bit)
- Preimage direnci: `digest_size` bit (max 256 bit)

**Örnek:**

```python
hashlib.blake2s(b"abc").hexdigest()
hashlib.blake2s(b"abc", digest_size=16).hexdigest()
hashlib.blake2s(b"mesaj", key=b"key").hexdigest()
```

### Önemli Yapısal Farklar

**Prefix Stability:**

SHAKE çıktısı **prefix-stable**'dır:
```
SHAKE128("abc", 16 byte) → X
SHAKE128("abc", 32 byte) → X + 16 byte daha
```

BLAKE2 çıktısı **prefix-stable DEĞİLDİR**:
```
BLAKE2b("abc", digest_size=16) → X
BLAKE2b("abc", digest_size=32) → Y (X ile alakasız!)
```

Bu, BLAKE2'de digest_size parameter block'a yazılıp h[0]'a XOR'landığı için olur — farklı boyutlardaki hash'ler farklı "domain" gibi davranır.

### Güvenlik Durumu

✅ BLAKE2 ailesi **kriptografik olarak güvenlidir**. Argon2 (şifre hashleme yarışması kazananı), WireGuard, IPFS, Zcash gibi modern projelerde kullanılır.

---

## Karşılaştırma Tablosu

### Genel Karşılaştırma

| Özellik | MD5 | SHA3-256 | BLAKE2b | BLAKE2s |
|---------|-----|----------|---------|---------|
| **Yapı** | Merkle-Damgård | Sponge | HAIFA | HAIFA |
| **Çıktı (varsayılan)** | 16 byte (sabit) | 32 byte (sabit) | 64 byte (değişken) | 32 byte (değişken) |
| **Block boyutu** | 64 byte | 136 byte (rate) | 128 byte | 64 byte |
| **Word boyutu** | 32 bit | 64 bit | 64 bit | 32 bit |
| **Round sayısı** | 64 | 24 | 12 | 10 |
| **Built-in MAC** | ❌ | ❌ | ✅ | ✅ |
| **Built-in salt** | ❌ | ❌ | ✅ | ✅ |
| **Değişken çıktı** | ❌ | ❌ (SHAKE hariç) | ✅ | ✅ |
| **Güvenli mi?** | ❌ Kırılmış | ✅ Güvenli | ✅ Güvenli | ✅ Güvenli |
| **Hız (yazılım)** | Çok hızlı | Orta | Çok hızlı | Hızlı |
| **Standart** | RFC 1321 | FIPS 202 | RFC 7693 | RFC 7693 |

### SHA-3 Ailesi İç Karşılaştırma

| Fonksiyon | Çıktı | Rate | Capacity | Collision Direnci |
|-----------|-------|------|----------|-------------------|
| SHA3-224 | 28 byte | 1152 bit | 448 bit | 112 bit |
| SHA3-256 | 32 byte | 1088 bit | 512 bit | 128 bit |
| SHA3-384 | 48 byte | 832 bit | 768 bit | 192 bit |
| SHA3-512 | 64 byte | 576 bit | 1024 bit | 256 bit |
| SHAKE128 | Değişken | 1344 bit | 256 bit | 128 bit |
| SHAKE256 | Değişken | 1088 bit | 512 bit | 256 bit |

### BLAKE2 Ailesi İç Karşılaştırma

| Özellik | BLAKE2b | BLAKE2s |
|---------|---------|---------|
| Hedef platform | 64-bit | 32-bit / IoT |
| Max çıktı | 64 byte | 32 byte |
| Max anahtar | 64 byte | 32 byte |
| Max salt | 16 byte | 8 byte |
| Max person | 16 byte | 8 byte |
| Block boyutu | 128 byte | 64 byte |
| Round sayısı | 12 | 10 |
| Max collision güvenliği | 256 bit | 128 bit |

---

## Hangi Algoritmayı Ne Zaman Kullanmalı?

| Senaryo | Önerilen Algoritma |
|---------|---------------------|
| Genel amaçlı hash | SHA3-256 veya BLAKE2b |
| Yüksek güvenlik (uzun vadeli) | SHA3-512 veya BLAKE2b (64 byte) |
| MAC (mesaj kimlik doğrulama) | BLAKE2b (key parametresi ile) veya HMAC-SHA3-256 |
| KDF (anahtar türetme) | BLAKE2b veya SHAKE256 |
| Rastgele bit / maske üretimi | SHAKE128 veya SHAKE256 |
| Şifre hashleme | **Argon2** (BLAKE2b temelli) — düz hash değil! |
| Dosya bütünlük kontrolü | BLAKE2b veya SHA3-256 |
| IoT / gömülü sistem | BLAKE2s |
| FIPS uyumluluğu gerekli | SHA-3 ailesi |
| Eski sistem uyumluluğu | MD5 (sadece non-güvenlik) |

## 4. Karşılaştırma Tablosu

| Algoritma | Özet Uzunluğu | Yapı | Güvenlik Durumu | Tipik Kullanım |
| :--- | :--- | :--- | :--- | :--- |
| **MD5** | 128 bit | Merkle-Damgård | ❌ Kırıldı | Eski sistemler |
| **SHA-3** | 224-512 bit | Sponge | ✅ Çok Güvenli | Modern Standart |
| **BLAKE2b** | 512 bit | ARX / HAIFA | ✅ Çok Güvenli | Performans (64-bit) |
| **BLAKE2s** | 256 bit | ARX / HAIFA | ✅ Çok Güvenli | Mobil / 32-bit |

---

## Kaynaklar

### MD5
- **RFC 1321:** https://datatracker.ietf.org/doc/html/rfc1321 — Resmi MD5 spesifikasyonu (R. Rivest, 1992)

### SHA-3
- **FIPS 202:** https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf — Resmi NIST standardı
- **Keccak resmi sitesi:** https://keccak.team/keccak_specs_summary.html — Permütasyon spesifikasyonu
- **NIST SP 800-185:** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf — Türetilmiş fonksiyonlar (cSHAKE, KMAC, TupleHash, ParallelHash)
- **Keccak referans dokümanı:** https://keccak.team/files/Keccak-reference-3.0.pdf

### BLAKE2
- **RFC 7693:** https://datatracker.ietf.org/doc/html/rfc7693 — IETF resmi spesifikasyonu
- **BLAKE2 resmi sitesi:** https://www.blake2.net/
- **Tasarım dokümanı:** https://www.blake2.net/blake2.pdf — "BLAKE2: simpler, smaller, fast as MD5"
- **Referans implementasyonu:** https://github.com/BLAKE2/BLAKE2

### Python
- **hashlib dokümantasyonu:** https://docs.python.org/3/library/hashlib.html — Yerleşik hash kütüphanesi

---

# Test Vektörleri
---

## Test Vektörleri Nedir?

Test vektörleri, bir hash algoritmasının doğru implemente edilip edilmediğini kontrol etmek için kullanılan **bilinen giriş-çıkış çiftleridir**. Her algoritmanın resmi test vektörleri, ilgili standart belgelerinde veya bağlı dokümanlarda yayınlanmıştır.

---

## MD5 Test Vektörleri

**Kaynak:** [RFC 1321 — Appendix A.5](https://datatracker.ietf.org/doc/html/rfc1321#appendix-A.5)

RFC 1321'in sonunda "MDTestSuite" başlığı altında 7 temel test vektörü yer alır. Bunlar herhangi bir MD5 implementasyonunu doğrulamak için yeterlidir.

### Örnek Vektörler

| Giriş | MD5 Çıkışı |
|-------|------------|
| `""` (boş) | `d41d8cd98f00b204e9800998ecf8427e` |
| `"a"` | `0cc175b9c0f1b6a831c399e269772661` |
| `"abc"` | `900150983cd24fb0d6963f7d28e17f72` |
| `"message digest"` | `f96b697d7cb7938d525a2f31aaf161d0` |
| `"abcdefghijklmnopqrstuvwxyz"` | `c3fcd3d76192e4007dfb496cca67e13b` |

---

## SHA-3 Test Vektörleri

### Resmi Kaynaklar

- **NIST CAVP — SHA-3 byte test vektörleri:**
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
- **NIST CAVP — SHAKE test vektörleri:**
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
- **NIST CAVP ana sayfası:**
  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
- **Keccak ekibi arşivi:**
  https://keccak.team/archives.html

> **Önemli not:** FIPS 202 standardının kendisi test vektörü içermez. Test vektörleri ayrı ZIP dosyalarında, `.rsp` (response) formatında dağıtılır. Her varyant için kısa mesaj (`ShortMsg`), uzun mesaj (`LongMsg`) ve Monte Carlo (`Monte`) dosyaları bulunur.

### Dosya Formatı Örneği (`.rsp`)

```
Len = 0
Msg = 00
MD = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

Len = 24
Msg = 616263
MD = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
```

### Örnek Vektörler

| Fonksiyon | Giriş | Çıkış |
|-----------|-------|-------|
| SHA3-256 | `""` | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` |
| SHA3-256 | `"abc"` | `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532` |
| SHA3-512 | `""` | `a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26` |
| SHA3-512 | `"abc"` | `b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0` |
| SHAKE128 (32 byte) | `""` | `7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26` |
| SHAKE256 (64 byte) | `""` | `46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be` |

### Türetilmiş Fonksiyonlar (KMAC, cSHAKE, TupleHash)

NIST SP 800-185 test örnekleri için: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

Bu sayfa adım adım hesaplama detayları içeren PDF örnekleri sunar.

---

## BLAKE2 Test Vektörleri

### Resmi Kaynaklar

- **RFC 7693 — Appendix A (BLAKE2b) ve Appendix B (BLAKE2s):**
  https://datatracker.ietf.org/doc/html/rfc7693
- **BLAKE2 resmi GitHub deposu (kapsamlı KAT):**
  https://github.com/BLAKE2/BLAKE2/tree/master/testvectors

> **RFC'nin avantajı:** SHA-3'ten farklı olarak BLAKE2 standardı, test vektörlerini **kendi içinde** barındırır. Appendix A'da BLAKE2b için "abc" girdisinin 12 round'unun ara state'leri adım adım gösterilir — implementasyonu debug etmek için ideal.

### Kapsamlı Testler İçin GitHub

`blake2-kat.json` dosyası **8000+** test vektörü içerir: anahtarsız mod, anahtarlı mod, farklı mesaj uzunlukları, farklı çıktı boyutları kapsanır.

### JSON Formatı Örneği

```json
{
  "hash": "blake2b",
  "in": "00",
  "key": "",
  "out": "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4..."
}
```

### Örnek Vektörler

| Fonksiyon | Giriş | Çıkış |
|-----------|-------|-------|
| BLAKE2b (64 byte) | `""` | `786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce` |
| BLAKE2b (64 byte) | `"abc"` | `ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923` |
| BLAKE2s (32 byte) | `""` | `69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9` |
| BLAKE2s (32 byte) | `"abc"` | `508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982` |

---

## Kaynak Özet Tablosu

| Algoritma | Test Vektörü Konumu | Vektör Sayısı |
|-----------|---------------------|---------------|
| MD5 | RFC 1321 Appendix A.5 (doküman içinde) | 7 temel |
| SHA-3 | NIST CAVP ZIP dosyaları (ayrı) | Binlerce |
| SHAKE | NIST CAVP ZIP dosyaları (ayrı) | Binlerce |
| BLAKE2 | RFC 7693 Appendix A/B + GitHub JSON | 8000+ |

---

### Önemli Kenar Durumları

Test vektörleri seçerken aşağıdaki durumlar mutlaka denenmelidir:

- **Boş giriş** — padding mantığını test eder
- **Block boyutu sınırları** — MD5/SHA-3 için padding boundary hatalarını yakalar
- **Tam block kadar veri** — sıfır padding durumlarını test eder
- **Uzun mesajlar** — counter overflow ve multi-block işleme hatalarını ortaya çıkarır
