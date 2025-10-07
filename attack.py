#!/usr/bin/env python3
import subprocess

ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out,_ = p.communicate(data)
    return out

def enc_once(raw_plain: bytes):
    out = run([ENC], raw_plain)
    return out[:16], out[16:32]

def add_le(b: bytes, step: int, n: int) -> bytes:
    v = int.from_bytes(b, "little")
    v = (v + (step * n)) & ((1 << 128) - 1)
    return v.to_bytes(16, "little")

def recover():
    secret = bytearray()

    iv1,_ = enc_once(b"")
    iv2,_ = enc_once(b"")
    step = (int.from_bytes(iv2, "little") - int.from_bytes(iv1, "little")) & ((1<<128)-1)
    if step == 0:
        raise RuntimeError("IV step is zero")

    ctr = add_le(iv2, step, 1)

    for i in range(1,17):
        k = 16 - i
        iv_real = add_le(ctr, step, 256)

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
            iv_g = add_le(iv_g, step, 1)

        real_prefix = iv_real[:k] + secret
        iv_used_real, c1_real = enc_once(real_prefix)

        if c1_real not in table:
            raise RuntimeError(f"match not found at byte {i}")
        gstar, last_g = table[c1_real]
        si = iv_real[15] ^ last_g ^ gstar
        secret.append(si)
        print(f"[+] byte {i:2d} = {si:02x}    secret_so_far = {secret.hex()}")

        ctr = add_le(iv_real, step, 1)

    print("\nSECRET (hex)  =", secret.hex())
    try:
        print("SECRET (ascii)= ", secret.decode("utf-8"))
    except:
        pass

if __name__ == "__main__":
    recover()
