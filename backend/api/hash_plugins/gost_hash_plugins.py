"""
HashRegistry plugins for GOST R 34.11-94 and GOST R 34.11-2012 (Streebog).

Uses standalone implementations in gost.python_impl (no PyPI dependency).
"""

from __future__ import annotations

from hash_registry import HashPlugin
from gost.python_impl import new_gost94, streebog_new


class GostR3411194HashPlugin(HashPlugin):
    @property
    def id(self) -> str:
        return "gost_r34_11_94"

    @property
    def name(self) -> str:
        return "GOST R 34.11-94"

    @property
    def description(self) -> str:
        return (
            "Russian GOST hash (256-bit digest), superseded by Streebog. "
            "RFC 5831."
        )

    @property
    def digest_size(self) -> int:
        return 32

    @property
    def sidebar_group(self) -> str:
        return "GOST Hash"

    @property
    def sidebar_icon(self) -> str:
        return "94"

    def compute_hash(self, data: bytes) -> bytes:
        return new_gost94(data).digest()


class Streebog256HashPlugin(HashPlugin):
    @property
    def id(self) -> str:
        return "streebog_256"

    @property
    def name(self) -> str:
        return "Streebog-256 (GOST R 34.11-2012)"

    @property
    def description(self) -> str:
        return "GOST R 34.11-2012 / Streebog with 256-bit digest. RFC 6986."

    @property
    def digest_size(self) -> int:
        return 32

    @property
    def sidebar_group(self) -> str:
        return "GOST Hash"

    @property
    def sidebar_icon(self) -> str:
        return "256"

    def compute_hash(self, data: bytes) -> bytes:
        h = streebog_new("streebog256", data=bytearray(data))
        return h.digest()


class Streebog512HashPlugin(HashPlugin):
    @property
    def id(self) -> str:
        return "streebog_512"

    @property
    def name(self) -> str:
        return "Streebog-512 (GOST R 34.11-2012)"

    @property
    def description(self) -> str:
        return "GOST R 34.11-2012 / Streebog with 512-bit digest. RFC 6986."

    @property
    def digest_size(self) -> int:
        return 64

    @property
    def sidebar_group(self) -> str:
        return "GOST Hash"

    @property
    def sidebar_icon(self) -> str:
        return "512"

    def compute_hash(self, data: bytes) -> bytes:
        h = streebog_new("streebog512", data=bytearray(data))
        return h.digest()
