def ksa_rc4(khoa: bytes) -> list:
    """Key scheduling algorithm: trộn hoán vị S[0..255] theo khóa."""
    if not khoa:
        raise ValueError("Khóa không được rỗng")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + khoa[i % len(khoa)]) % 256
        S[i], S[j] = S[j], S[i]
    return S
 
 
def prga_rc4(S: list, so_byte: int) -> bytes:
    """Pseudo-random generation algorithm: sinh `so_byte` byte dãy khóa.
    Làm việc trên bản sao của S nên không làm hỏng S gốc."""
    S = S[:]
    i = j = 0
    out = bytearray()
    for _ in range(so_byte):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return bytes(out)
 
 
def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """Mã hóa hoặc giải mã: data XOR dãy khóa RC4(key)."""
    if isinstance(data, str) or isinstance(key, str):
        raise TypeError("data và key phải là bytes (dùng .encode('utf-8'))")
    ks = prga_rc4(ksa_rc4(key), len(data))
    return bytes(d ^ k for d, k in zip(data, ks))
 
 
def ma_hoa_rc4(ban_ro: bytes, khoa: bytes) -> bytes:
    return rc4_crypt(ban_ro, khoa)
 
 
def giai_ma_rc4(ban_ma: bytes, khoa: bytes) -> bytes:
    return rc4_crypt(ban_ma, khoa)
