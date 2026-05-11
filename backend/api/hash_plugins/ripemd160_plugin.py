from hash_registry import HashPlugin

try:
    from hash_plugins.ripemd160_core import ripemd160
except ImportError:
    from ripemd160_core import ripemd160


class RIPEMD160Plugin(HashPlugin):
    """
    RIPEMD-160 hash plugin.
    Pure Python implementation — hashlib kullanılmaz.
    Digest: 160-bit (20 byte)
    """

    @property
    def id(self) -> str:
        return "ripemd160"

    @property
    def name(self) -> str:
        return "RIPEMD-160"

    @property
    def description(self) -> str:
        return (
            "RACE Integrity Primitives Evaluation Message Digest — 160-bit. "
            "Pure Python implementasyon, hashlib kullanılmaz. "
            "Bitcoin adres üretiminde (HASH160) yaygın olarak kullanılır."
        )

    @property
    def digest_size(self) -> int:
        return 20

    def compute_hash(self, data: bytes) -> bytes:
        return ripemd160(data)
