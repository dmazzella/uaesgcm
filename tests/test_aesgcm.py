from _aesgcm import ciphers
# from os import urandom


def main():
    data = b"a secret message"

    aad = b"" #b"\xDE\xAD\xBE\xEF"
    key = b'\xd1}\x9c"e\x0c\xe0\xafb\x1c\xf3J^\xd7\xa7y<\x17\xdd\xed`eD\x051\xae\xbb\xa2\x91\xfeD\xe1'
    nonce = b"7M\xb4xy\x01t\x88\xd8\xf3\x9e\xc0"

    aesgcm = ciphers.AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, aad)
    print(ct)
    dt = aesgcm.decrypt(nonce, ct, aad)
    print(dt)

    # key_g = ciphers.AESGCM.generate_key(256)
    # print(key_g)
    # nonce_g = urandom(12)
    # print(nonce_g)


if __name__ == "__main__":
    main()
