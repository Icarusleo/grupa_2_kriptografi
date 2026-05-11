import sys
import os
from pathlib import Path

# Add the parent directory to sys.path so we can import from sha2
# This is needed because the registry loads plugins from the hash_plugins directory
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from sha2 import sha2 as sha2_impl
from hash_registry import HashPlugin

class SHA224Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha224"

    @property
    def name(self) -> str:
        return "SHA-224"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 2 with 224-bit digest size."
        
    @property
    def digest_size(self) -> int:
        return 28

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha224(data)

class SHA256Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha256"

    @property
    def name(self) -> str:
        return "SHA-256"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 2 with 256-bit digest size. Widely used in security protocols."
        
    @property
    def digest_size(self) -> int:
        return 32

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha256(data)

class SHA384Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha384"

    @property
    def name(self) -> str:
        return "SHA-384"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 2 with 384-bit digest size. Part of the SHA-2 family."
        
    @property
    def digest_size(self) -> int:
        return 48

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha384(data)

class SHA512Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha512"

    @property
    def name(self) -> str:
        return "SHA-512"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 2 with 512-bit digest size. Strongest of the SHA-2 family."
        
    @property
    def digest_size(self) -> int:
        return 64

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha512(data)

class SHA512_224Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha512-224"

    @property
    def name(self) -> str:
        return "SHA-512/224"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 2 using SHA-512 core with 224-bit truncation."
        
    @property
    def digest_size(self) -> int:
        return 28

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha512_224(data)

class SHA512_256Plugin(HashPlugin):
    @property
    def id(self) -> str:
        return "sha512-256"

    @property
    def name(self) -> str:
        return "SHA-512/256"

    @property
    def description(self) -> str:
        return "Secure Hash Algorithm 2 using SHA-512 core with 256-bit truncation."
        
    @property
    def digest_size(self) -> int:
        return 32

    def compute_hash(self, data: bytes) -> bytes:
        return sha2_impl.sha512_256(data)
