# GOST hash — input / output pairs

| Algorithm | Input | Output (hex digest) | Source |
|-----------|--------|---------------------|--------|
| GOST R 34.11-94 | ASCII string `This is message, length=32 bytes` (32 bytes) | `b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa` | [RFC 5831 §7.3.1](https://www.rfc-editor.org/rfc/rfc5831.html#section-7.3) |
| GOST R 34.11-94 | ASCII string `Suppose the original message has length = 50 bytes` (50 bytes) | `471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208` | [RFC 5831 §7.3.2](https://www.rfc-editor.org/rfc/rfc5831.html#section-7.3) |
| Streebog-256 | Empty message (length 0) | `3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb` | [RFC 6986 §10.1](https://www.rfc-editor.org/rfc/rfc6986.html#section-10.1) |
| Streebog-512 | Empty message (length 0) | `8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a` | [RFC 6986 §10.1](https://www.rfc-editor.org/rfc/rfc6986.html#section-10.1) |
| Streebog-256 | ASCII string `012345678901234567890123456789012345678901234567890123456789012` (63 bytes, RFC “M1”) | `9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500` | [RFC 6986 §10.1 Example 1](https://www.rfc-editor.org/rfc/rfc6986.html#section-10.1) |
| Streebog-512 | Same 63-byte ASCII string as above | `1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48` | [RFC 6986 §10.1 Example 1](https://www.rfc-editor.org/rfc/rfc6986.html#section-10.1) |
