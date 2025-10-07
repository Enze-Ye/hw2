import subprocess, binascii

NX  = "/project/web-classes/Fall-2025/csci5471/hw2/next_iv"
ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out,_ = p.communicate(data)
    return out

def enc_once(raw_plain: bytes):
    out = run([ENC], raw_plain)
    return out[:16], out[16:32]

def inc_big(b: bytes) -> bytes:
    x = int.from_bytes(b, "big"); x = (x + 1) & ((1<<128)-1)
    return x.to_bytes(16, "big")

def inc_little(b: bytes) -> bytes:
    a = bytearray(b); carry = 1
    for i in range(16):
        v = a[i] + carry
        a[i] = v & 0xff
        carry = v >> 8
        if carry == 0: break
    return bytes(a)

def inc_n(b: bytes, n: int, inc_fn):
    x = b
    for _ in range(n): x = inc_fn(x)
    return x

def recover():
    secret = bytearray()

    iv1,_ = enc_once(b"")  
    iv2,_ = enc_once(b"")        

    inc_fn = inc_big if inc_big(iv1)==iv2 else inc_little if inc_little(iv1)==iv2 else None
    if inc_fn is None: raise RuntimeError("IV increment not detected")

    ctr = inc_fn(iv2)      

    for i in range(1,17):
        k = 16 - i

        iv_real = inc_n(ctr, 256, inc_fn)

        table = {}
        iv_g = ctr
        for g in range(256):
            p1 = bytearray(16)
            p1[:k] = iv_g[:k]
            for idx in range(len(secret)):
                j = k + idx
                p1[j] = iv_g[j] ^ iv_real[j] ^ secret[idx]
            p1[15] = g
            iv_used, c1 = enc_once(bytes(p1))
            table[c1] = (g, iv_g[15])
            iv_g = inc_fn(iv_g)

        real_prefix = iv_real[:k] + secret
        iv_used_real, c1_real = enc_once(real_prefix)

        if c1_real not in table:
            raise RuntimeError(f"match not found at byte {i}")
        gstar, last_g = table[c1_real]
        si = iv_real[15] ^ last_g ^ gstar
        secret.append(si)
        print(f"[+] byte {i:2d} = {si:02x}    secret_so_far = {secret.hex()}")

        ctr = inc_fn(iv_real)

    print("\nSECRET (hex)  =", secret.hex())
    try:
        print("SECRET (ascii)= ", secret.decode("utf-8"))
    except:
        pass

if __name__ == "__main__":
    recover()
