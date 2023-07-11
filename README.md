
# uaesgcm

---------------

### Compiling the cmodule into MicroPython

To build such a module, compile MicroPython with an extra make flag named ```USER_C_MODULES``` set to the directory containing all modules you want included (not to the module itself).

### Compiling the cmodule into unix port

```bash
$ git clone https://github.com/micropython/uaesgcm.git
$ cd micropython
micropython$ git submodule update --init --depth 1
micropython$ git clone https://github.com/dmazzella/uaesgcm.git usercmodule/uaesgcm
micropython$ make -j2 -C mpy-cross/
micropython$ make -j2 -C ports/unix/ MICROPY_PY_BTREE=0 MICROPY_SSL_MBEDTLS=1 USER_C_MODULES="$(pwd)/usercmodule"
```

```python
from _aesgcm import ciphers

data = b"a secret message"

aad = b"\xDE\xAD\xBE\xEF"
key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
nonce = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"

aesgcm = ciphers.AESGCM(key)
ct = aesgcm.encrypt(nonce, data, aad)
dt = aesgcm.decrypt(nonce, ct, aad)
```
