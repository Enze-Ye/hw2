#!/usr/bin/env python3
import subprocess, binascii

NX  = "/project/web-classes/Fall-2025/csci5471/hw2/next_iv"
ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out,_ = p.communicate(data)
    return out

def next_iv_bytes() -> bytes:
    return run([NX])

def enc_first_block(raw_plain: bytes) -> bytes:
    out = run([ENC], raw_plain)
    return out[:16], out[16:32]

def inc128(b: bytes) -> bytes:
    x = int.from_bytes(b, "big")
    x = (x + 1) & ((1 << 128) - 1)
    return x.to_bytes(16, "big")

def add128(b: bytes, n: int) -> bytes:
    x = int.from_bytes(b, "big")
    x = (x + n) & ((1 << 128) - 1)
    return x.to_bytes(16, "big")

def recover():
    secret = bytearray()
    ctr0 = next_iv_bytes()
    ctr  = inc128(ctr0)
    for i in range(1, 17):
        k = 16 - i
        iv_real = add128(ctr, 256)
        table = {}
        for g in range(256):
            iv_g = ctr
            p1 = bytearray(16)
            p1[:k] = iv_g[:k]
            for idx in range(len(secret)):
                j = k + idx
                p1[j] = iv_g[j] ^ iv_real[j] ^ secret[idx]
            p1[15] = g
            iv_used, c1 = enc_first_block(bytes(p1))
            table[c1] = (g, iv_g[15])
            ctr = inc128(ctr)
        real_prefix = iv_real[:k] + secret
        iv_used_real, c1_real = enc_first_block(real_prefix)
        ctr = inc128(ctr)
        if c1_real not in table:
            raise RuntimeError(f"match not found at byte {i}")
        gstar, last_g = table[c1_real]
        si = iv_real[15] ^ last_g ^ gstar
        secret.append(si)
        print(f"[+] byte {i:2d} = {si:02x}    secret_so_far = {secret.hex()}")
    print("\nSECRET (hex)  =", secret.hex())
    try:
        print("SECRET (ascii)= ", secret.decode("utf-8"))
    except:
        pass

if __name__ == "__main__":
    recover()
