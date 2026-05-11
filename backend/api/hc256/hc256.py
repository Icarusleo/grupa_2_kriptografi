MASK32 = 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def _u32_from_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


class HC256:
    """
    Pure Python HC-256 stream cipher.

    Key: 32 bytes / 256 bits
    IV:  32 bytes / 256 bits

    Encryption and decryption are the same:
        output = input XOR keystream
    """

    KEY_SIZE = 32
    IV_SIZE = 32

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"HC-256 key must be 32 bytes, got {len(key)}")
        if len(iv) != self.IV_SIZE:
            raise ValueError(f"HC-256 IV/nonce must be 32 bytes, got {len(iv)}")

        self.P = [0] * 1024
        self.Q = [0] * 1024
        self.counter = 0

        self._init_state(key, iv)

    @staticmethod
    def _f1(x: int) -> int:
        return (_rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)) & MASK32

    @staticmethod
    def _f2(x: int) -> int:
        return (_rotr32(x, 17) ^ _rotr32(x, 19) ^ (x >> 10)) & MASK32

    def _g1(self, x: int, y: int) -> int:
        return (
            (_rotr32(x, 10) ^ _rotr32(y, 23))
            + self.Q[(x ^ y) & 0x3FF]
        ) & MASK32

    def _g2(self, x: int, y: int) -> int:
        return (
            (_rotr32(x, 10) ^ _rotr32(y, 23))
            + self.P[(x ^ y) & 0x3FF]
        ) & MASK32

    def _h1(self, x: int) -> int:
        a = x & 0xFF
        b = (x >> 8) & 0xFF
        c = (x >> 16) & 0xFF
        d = (x >> 24) & 0xFF

        return (
            self.Q[a]
            + self.Q[256 + b]
            + self.Q[512 + c]
            + self.Q[768 + d]
        ) & MASK32

    def _h2(self, x: int) -> int:
        a = x & 0xFF
        b = (x >> 8) & 0xFF
        c = (x >> 16) & 0xFF
        d = (x >> 24) & 0xFF

        return (
            self.P[a]
            + self.P[256 + b]
            + self.P[512 + c]
            + self.P[768 + d]
        ) & MASK32

    def _init_state(self, key: bytes, iv: bytes) -> None:
        W = [0] * 2560

        for i in range(8):
            W[i] = _u32_from_le(key, 4 * i)

        for i in range(8):
            W[i + 8] = _u32_from_le(iv, 4 * i)

        for i in range(16, 2560):
            W[i] = (
                self._f2(W[i - 2])
                + W[i - 7]
                + self._f1(W[i - 15])
                + W[i - 16]
                + i
            ) & MASK32

        self.P = W[512:1536]
        self.Q = W[1536:2560]
        self.counter = 0

        # HC-256 initialization: run 4096 steps and discard output.
        for _ in range(4096):
            self._next_word()

    def _next_word(self) -> int:
        i = self.counter & 0x3FF

        i3 = (i - 3) & 0x3FF
        i10 = (i - 10) & 0x3FF
        i12 = (i - 12) & 0x3FF
        i1023 = (i - 1023) & 0x3FF

        if self.counter < 1024:
            self.P[i] = (
                self.P[i]
                + self.P[i10]
                + self._g1(self.P[i3], self.P[i1023])
            ) & MASK32

            word = self._h1(self.P[i12]) ^ self.P[i]

        else:
            self.Q[i] = (
                self.Q[i]
                + self.Q[i10]
                + self._g2(self.Q[i3], self.Q[i1023])
            ) & MASK32

            word = self._h2(self.Q[i12]) ^ self.Q[i]

        self.counter = (self.counter + 1) & 0x7FF

        return word & MASK32

    def keystream(self, length: int) -> bytes:
        out = bytearray()

        while len(out) < length:
            out.extend(self._next_word().to_bytes(4, "little"))

        return bytes(out[:length])

    def crypt(self, data: bytes) -> bytes:
        ks = self.keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, ks))


def hc256_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return HC256(key, nonce).crypt(data)


if __name__ == "__main__":
    key = bytes.fromhex("00" * 32)
    iv = bytes.fromhex("00" * 32)

    plaintext = bytes.fromhex("00" * 64)

    # HC-256 zero key / zero IV, first 64 keystream bytes.
    # The published vector is often shown as 32-bit words, so each word appears
    # byte-reversed compared with the actual byte stream.
    expected_ciphertext = bytes.fromhex(
        "5b078985d8f6f30d42c5c02fa6b67951"
        "53f06534801f89f24e74248b720b4818"
        "cd9227ecebcf4dbf8dbf6977e4ae14f"
        "ae8504c7bc8a9f3ea6c0106f5327e6981"
    )

    got = hc256_crypt(key, iv, plaintext)

    print(got.hex())

    assert got == expected_ciphertext

    pt = b"patates"
    ct = hc256_crypt(key, iv, pt)
    dec = hc256_crypt(key, iv, ct)

    assert dec == pt

    print("HC-256 test passed.")