"""
Rabbit Stream Cipher Test Suite
Test vectors from RFC 4503 (https://tools.ietf.org/html/rfc4503)
Converted from Java JUnit test to Python.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from Rabbit_Cipher import Rabbit


def hex_to_bytes(hex_str):
    """Convert hex string like '91 28 13 29' to bytes."""
    if hex_str is None:
        return None
    return bytes([int(x, 16) for x in hex_str.split()])


def reverse_bytes(data):
    """Reverse entire byte array (endianness conversion)."""
    return data[::-1]


def reverse_output_blocks(data, block_size=16):
    """Reverse each 16-byte block independently (endianness conversion)."""
    result = bytearray()
    for i in range(0, len(data), block_size):
        result.extend(data[i:i + block_size][::-1])
    return bytes(result)


# ─── RFC 4503 Test Vectors (Java/big-endian byte order) ───
# Each tuple: (key_hex, iv_hex_or_None, expected_output_hex)
TEST_DATA = [
    # Test 1: key=0x00..00, no IV
    (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        None,
        "B1 57 54 F0 36 A5 D6 EC F5 6B 45 26 1C 4A F7 02 "
        "88 E8 D8 15 C5 9C 0C 39 7B 69 6C 47 89 C6 8A A7 "
        "F4 16 A1 C3 70 0C D4 51 DA 68 D1 88 16 73 D6 96"
    ),
    # Test 2: key=0x9128...C3AC, no IV
    (
        "91 28 13 29 2E 3D 36 FE 3B FC 62 F1 DC 51 C3 AC",
        None,
        "3D 2D F3 C8 3E F6 27 A1 E9 7F C3 84 87 E2 51 9C "
        "F5 76 CD 61 F4 40 5B 88 96 BF 53 AA 85 54 FC 19 "
        "E5 54 74 73 FB DB 43 50 8A E5 3B 20 20 4D 4C 5E"
    ),
    # Test 3: key=0x8395...0043, no IV
    (
        "83 95 74 15 87 E0 C7 33 E9 E9 AB 01 C0 9B 00 43",
        None,
        "0C B1 0D CD A0 41 CD AC 32 EB 5C FD 02 D0 60 9B "
        "95 FC 9F CA 0F 17 01 5A 7B 70 92 11 4C FF 3E AD "
        "96 49 E5 DE 8B FC 7F 3F 92 41 47 AD 3A 94 74 28"
    ),
    # Test 4: key=0x00..00, iv=0x00..00
    (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        "00 00 00 00 00 00 00 00",
        "C6 A7 27 5E F8 54 95 D8 7C CD 5D 37 67 05 B7 ED "
        "5F 29 A6 AC 04 F5 EF D4 7B 8F 29 32 70 DC 4A 8D "
        "2A DE 82 2B 29 DE 6C 1E E5 2B DB 8A 47 BF 8F 66"
    ),
    # Test 5: key=0x00..00, iv=0xC373F575C1267E59
    (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        "C3 73 F5 75 C1 26 7E 59",
        "1F CD 4E B9 58 00 12 E2 E0 DC CC 92 22 01 7D 6D "
        "A7 5F 4E 10 D1 21 25 01 7B 24 99 FF ED 93 6F 2E "
        "EB C1 12 C3 93 E7 38 39 23 56 BD D0 12 02 9B A7"
    ),
    # Test 6: key=0x00..00, iv=0xA6EB561AD2F41727
    (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        "A6 EB 56 1A D2 F4 17 27",
        "44 5A D8 C8 05 85 8D BF 70 B6 AF 23 A1 51 10 4D "
        "96 C8 F2 79 47 F4 2C 5B AE AE 67 C6 AC C3 5B 03 "
        "9F CB FC 89 5F A7 1C 17 31 3D F0 34 F0 15 51 CB"
    ),
]

INPUT = b"\x00" * 48  # 48 bytes of zeros


def convert_key(key_bytes):
    """Convert key from big-endian (RFC) to little-endian (Python impl)."""
    return reverse_bytes(key_bytes)


def convert_iv(iv_bytes):
    """Convert IV from big-endian (RFC) to little-endian (Python impl)."""
    return reverse_bytes(iv_bytes)


def convert_expected_output(out_bytes):
    """Convert expected output: reverse each 16-byte block."""
    return reverse_output_blocks(out_bytes)


def test_appendix_b_debug_vectors():
    print("\n--- Running Appendix B Debugging Vectors ---")
    
    # B.1. Testing Round Function and Key Setup
    # Note: RFC text has a typo in key (2E ED instead of 2E 3D).
    # The inner state proves 2E 3D was actually used.
    key_hex = "91 28 13 29 2E 3D 36 FE 3B FC 62 F1 DC 51 C3 AC"
    key = convert_key(hex_to_bytes(key_hex))
    
    cipher = Rabbit(key, b"")
    
    expected_m_x = [
        0x1D059312, 0xBDDC3E45, 0xF440927D, 0x50CBB553,
        0x36709423, 0x0B6F0711, 0x3ADA3A7B, 0xEB9800C8
    ]
    expected_m_c = [
        0x5DA1EF57, 0x22E9312F, 0xDCACFF87, 0x9B5784FA,
        0x0DE43C8C, 0xBC5679B8, 0x63841B4C, 0x8E9623AA
    ]
    
    assert cipher.ctx.m.carry == False, "B.1 Key Setup 'b' mismatch"
    assert cipher.ctx.m.x == expected_m_x, "B.1 Key Setup 'X' mismatch"
    assert cipher.ctx.m.c == expected_m_c, "B.1 Key Setup 'C' mismatch"
    print("Test B.1 (Key Setup inner state): PASSED")
    
    cipher.crypt(b"\x00" * 48)
    expected_w_x = [
        0xB5428566, 0xA2593617, 0xFF5578DE, 0x7293950F,
        0x145CE109, 0xC93875B0, 0xD34306E0, 0x43FEEF87
    ]
    expected_w_c = [
        0x45406940, 0x9CD0CFA9, 0x7B26E725, 0x82F5FEE2,
        0x87CBDB06, 0x5AD06156, 0x4B229534, 0x087DC224
    ]
    
    assert cipher.ctx.w.carry == True, "B.1 Post-Output 'b' mismatch"
    assert cipher.ctx.w.x == expected_w_x, "B.1 Post-Output 'X' mismatch"
    assert cipher.ctx.w.c == expected_w_c, "B.1 Post-Output 'C' mismatch"
    print("Test B.1 (Post-Output inner state): PASSED")

    # B.2. Testing the IV Setup
    iv = convert_iv(hex_to_bytes("C3 73 F5 75 C1 26 7E 59"))
    
    cipher2 = Rabbit(key, iv)
    
    expected_iv_x = [
        0x6274E424, 0xE14CE120, 0xDA8739D9, 0x65E0402D,
        0xD1281D10, 0xBD435BAA, 0x4E9E7A02, 0x9B467ABD
    ]
    expected_iv_c = [
        0xD15ADE44, 0x2ECFC356, 0xF32C3FC6, 0xA2F647D7,
        0x19F71622, 0x5272ED72, 0xD5CB3B6E, 0xC9183140
    ]
    
    assert cipher2.ctx.w.carry == True, "B.2 IV Setup 'b' mismatch"
    assert cipher2.ctx.w.x == expected_iv_x, "B.2 IV Setup 'X' mismatch"
    assert cipher2.ctx.w.c == expected_iv_c, "B.2 IV Setup 'C' mismatch"
    print("Test B.2 (IV Setup inner state): PASSED")


def run_tests():
    passed = 0
    failed = 0

    for i, (key_hex, iv_hex, out_hex) in enumerate(TEST_DATA, 1):
        # Parse hex strings
        key_raw = hex_to_bytes(key_hex)
        expected_raw = hex_to_bytes(out_hex)

        # Convert byte order for the Python implementation
        key = convert_key(key_raw)
        expected = convert_expected_output(expected_raw)

        if iv_hex is not None:
            iv_raw = hex_to_bytes(iv_hex)
            iv = convert_iv(iv_raw)
        else:
            iv = b""

        # Encrypt
        cipher = Rabbit(key, iv)
        result = cipher.crypt(INPUT)

        # Compare
        if result == expected:
            print(f"Test {i}: PASSED")
            passed += 1
        else:
            print(f"Test {i}: FAILED")
            print(f"  Expected: {expected.hex()}")
            print(f"  Got:      {result.hex()}")
            failed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed}/{passed + failed} tests passed")
    
    try:
        test_appendix_b_debug_vectors()
    except Exception as e:
        print(f"Appendix B Debug Vectors FAILED: {e}")
        failed += 1

    if failed:
        print(f"\n{failed} test(s) FAILED!")
        return False
    else:
        print("\nAll tests passed!")
        return True


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
