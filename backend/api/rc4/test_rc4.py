import codecs
import sys
sys.path.insert(0, r"C:\Users\asliy\Desktop\rc4_src")

MOD = 256

def KSA(key):
    key_length = len(key)
    S = list(range(MOD))
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % MOD]
        yield K

def rc4(key_hex, data_hex):
    key = [int(key_hex[i:i+2], 16) for i in range(0, len(key_hex), 2)]
    data = bytes.fromhex(data_hex)
    S = KSA(key)
    keystream = PRGA(S)
    return bytes([b ^ next(keystream) for b in data]).hex()

print("=" * 55)
print("        RC4 INTERACTIVE TEST")
print("=" * 55)

while True:
    print("\n[1] Encrypt")
    print("[2] Decrypt")
    print("[3] Cikis")
    sec = input("\nSecim: ").strip()

    if sec == "3":
        print("Cikiliyor...")
        break
    if sec not in ("1","2"):
        print("Gecersiz!")
        continue

    key = input("\nKEY (hex, bos=default): ").strip().replace(" ","")
    if not key:
        key = "0102030405"
        print(f"  -> Default: {key}")

    label = "PLAINTEXT" if sec=="1" else "CIPHERTEXT"
    data = input(f"{label} (hex, t: ile metin): ").strip().replace(" ","")
    if data.lower().startswith("t:"):
        data = data[2:].strip().encode().hex()
        print(f"  -> Hex: {data}")

    try:
        result = rc4(key, data)
        print("\n" + "-"*55)
        out_label = "CIPHERTEXT" if sec=="1" else "PLAINTEXT"
        print(f"  {out_label} : {result}")
        if sec == "2":
            try:
                print(f"  METIN      : {bytes.fromhex(result).decode()}")
            except: pass
        print("-"*55)
    except Exception as e:
        print(f"  HATA: {e}")
