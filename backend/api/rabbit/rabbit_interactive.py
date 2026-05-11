import sys
from rabbit_wrapper import encrypt_bytes, decrypt_bytes

def main():
    print("=" * 45)
    print(" Rabbit Stream Cipher - Basit Interaktif Test")
    print("=" * 45)
    print()
    
    # Kullanicidan sifrelenecek metni al
    try:
        plaintext = input("1. Lutfen sifrelenecek metni girin: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCikis yapildi.")
        sys.exit(0)
        
    if not plaintext:
        print("Hata: Metin bos olamaz!")
        sys.exit(1)
        
    # Kullanicidan anahtar al (16 karakter = 16 byte)
    try:
        key_input = input("2. 16 karakterlik bir anahtar girin (Orn: 0123456789abcdef): ")
    except (EOFError, KeyboardInterrupt):
        print("\nCikis yapildi.")
        sys.exit(0)
        
    # Eger anahtar kisa ise boslukla tamamla, uzunsa kes
    key_input = key_input.ljust(16, ' ')[:16]
    
    data = plaintext.encode('utf-8')
    key = key_input.encode('utf-8')
    
    print("\n--- ISLEM BASLIYOR ---")
    print(f"Kullanilan Anahtar: '{key_input}'")
    
    # Sifreleme islemi
    encrypted_data = encrypt_bytes(key, data)
    print(f"\n[+] Sifrelenmis Veri (Hex formatinda): {encrypted_data.hex()}")
    
    # Sifre cozme islemi
    decrypted_data = decrypt_bytes(key, encrypted_data)
    print(f"[+] Cozulmus Veri (Orijinal Metin):  {decrypted_data.decode('utf-8')}")
    
    print("\nIslem basariyla tamamlandi!")

if __name__ == "__main__":
    main()
