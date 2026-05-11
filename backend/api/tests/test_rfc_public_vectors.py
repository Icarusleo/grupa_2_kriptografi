"""
Published test vectors from RFC 5831 (GOST R 34.11-94) and RFC 6986 (Streebog).

RFCs interleave 32-bit words in a fixed order; for 5831 §7.3 the concatenation
of those words (big-endian per word) yields bytes that are the **reverse** of
the usual ASCII message. Here we use either explicit ASCII or the [::-1] rule.

Sources:
  https://www.rfc-editor.org/rfc/rfc5831.html  (§7.3)
  https://www.rfc-editor.org/rfc/rfc6986.html  (§10.1)
"""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

API_ROOT = Path(__file__).resolve().parent.parent
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))


def _gost94_rfc_words_to_digest_be(ws: list[str]) -> bytes:
    """RFC 5831 lists eight 32-bit words (MSW first); implementation stores LE words reversed."""
    return b"".join(struct.pack("<I", int(w, 16)) for w in reversed(ws))


class TestRFC5831Gost94(unittest.TestCase):
    def test_section_7_3_1_32_byte_message(self) -> None:
        from gost.python_impl import new_gost94

        msg = (
            b"This is message, length=32 bytes"
        )
        self.assertEqual(len(msg), 32)
        rfc_h_words = [
            "FAFF37A6",
            "15A81669",
            "1CFF3EF8",
            "B68CA247",
            "E09525F3",
            "9F811983",
            "2EB81975",
            "D366C4B1",
        ]
        expected = _gost94_rfc_words_to_digest_be(rfc_h_words)
        self.assertEqual(new_gost94(msg).digest(), expected)

    def test_section_7_3_2_50_byte_message(self) -> None:
        from gost.python_impl import new_gost94

        msg = (
            b"Suppose the original message has length = 50 bytes"
        )
        self.assertEqual(len(msg), 50)
        rfc_h_words = [
            "0852F562",
            "3B89DD57",
            "AEB4781F",
            "E54DF14E",
            "EAFBC135",
            "0613763A",
            "0D770AA6",
            "57BA1A47",
        ]
        expected = _gost94_rfc_words_to_digest_be(rfc_h_words)
        self.assertEqual(new_gost94(msg).digest(), expected)


class TestRFC6986Streebog(unittest.TestCase):
    """M1 = 504 bits: ASCII digit pattern; digests as printed in RFC (MSB-first) require [::-1]."""

    @staticmethod
    def _m1_63_bytes() -> bytes:
        words_le = [
            0x3736353433323130,
            0x3534333231303938,
            0x3332313039383736,
            0x3130393837363534,
            0x3938373635343332,
            0x3736353433323130,
            0x3534333231303938,
            0x0032313039383736,
        ]
        block = b"".join(struct.pack("<Q", w) for w in words_le)
        return block[:63]

    def test_example_1_streebog512(self) -> None:
        from gost.python_impl import streebog_new

        m1 = self._m1_63_bytes()
        rfc_hex = (
            "486f64c1917879417fef082b3381a4e2"
            "11c324f074654c38823a7b76f830ad00"
            "fa1fbae42b1285c0352f227524bc9ab1"
            "6254288dd6863dccd5b9f54a1ad0541b"
        )
        got = streebog_new("streebog512", data=bytearray(m1)).digest()
        self.assertEqual(got[::-1].hex(), rfc_hex)

    def test_example_1_streebog256(self) -> None:
        from gost.python_impl import streebog_new

        m1 = self._m1_63_bytes()
        rfc_hex = (
            "00557be5e584fd52a449b16b0251d05d"
            "27f94ab76cbaa6da890b59d8ef1e159d"
        )
        got = streebog_new("streebog256", data=bytearray(m1)).digest()
        self.assertEqual(got[::-1].hex(), rfc_hex)


if __name__ == "__main__":
    unittest.main()
