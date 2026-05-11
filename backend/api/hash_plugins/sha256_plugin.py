import hashlib
from hash_registry import HashPlugin

class SHA256Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha256"

    @property
    def name(self) -> str:
        return "SHA-256"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 256-bit. A cryptographic hash function outputting a 256-bit digest."
        
    @property
    def digest_size(self) -> int:
        return 32

    @property
    def block_size(self) -> int:
        return 64

    @property
    def rounds(self) -> int:
        return 64

    def compute_hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()
