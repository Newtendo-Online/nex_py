from __future__ import annotations


class RC4:
    def __init__(self, key: bytes):
        if not 1 <= len(key) <= 256:
            raise ValueError("RC4: la clé doit faire entre 1 et 256 octets")
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self._s = s
        self._i = 0
        self._j = 0

    def xor_key_stream(self, data: bytes) -> bytes:
        s, i, j = self._s, self._i, self._j
        out = bytearray(len(data))
        for n, b in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
        self._i, self._j = i, j
        return bytes(out)
