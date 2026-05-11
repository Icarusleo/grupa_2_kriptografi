# Auxiliary helpers for vendored Streegog (gost_34_11_2012.py).
#
# add_xor() is adapted from gostcrypto (MIT), Evgeny Drobotun (c) 2020:
# https://github.com/drobotun/gostcrypto/blob/master/gostcrypto/utils/utils.py
#
# ObjectIdentifier is a minimal shim replacing gostcrypto.gostoid.ObjectIdentifier:
# only construction with a dotted OID string is needed for hashing.


def add_xor(op_a: bytearray, op_b: bytearray) -> bytearray:
    op_a = bytearray(op_a)
    op_b = bytearray(op_b)
    result_len = min(len(op_a), len(op_b))
    result = bytearray(result_len)
    for i in range(result_len):
        result[i] = op_a[i] ^ op_b[i]
    return result


class ObjectIdentifier:
    """Minimal stand-in: stores dotted OID and integer tuple."""

    def __init__(self, dotted: str) -> None:
        self._dotted = dotted
        self.digit = tuple(int(x) for x in dotted.split('.'))
