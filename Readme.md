# RIPEMD-160 — Test Vektörleri

Pure Python implementasyon, `hashlib` kullanılmaz.  
Kaynak: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

```text
Input  : "" (boş string)
Output : 9c1185a5c5e9fc54612808977ee8f548b2258d31

Input  : "abc"
Output : 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc

Input  : "message digest"
Output : 5d0689ef49d2fae572b881b123a85ffa21595f36

Input  : "abcdefghijklmnopqrstuvwxyz"
Output : f71c27109c692c1b56bbdceb5b9d2865b3708dbc

Input  : "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
Output : 12a053384a9c0c88e405a06c27dcf49ada62eb2b
```
