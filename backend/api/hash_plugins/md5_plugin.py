import hashlib
from hash_registry import HashPlugin

class MD5Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "md5"

    @property
    def name(self) -> str:
        return "MD5"

    @property
    def description(self) -> str:
        return "Message-Digest Algorithm 5. A widely used 128-bit hash function (now considered cryptographically broken)."
        
    @property
    def digest_size(self) -> int:
        return 16

    def compute_hash(self, data: bytes) -> bytes:
        return hashlib.md5(data).digest()
