#!/usr/bin/env python3
import subprocess

NX  = "/project/web-classes/Fall-2025/csci5471/hw2/next_iv"
ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out,_ = p.communicate(data)
    return out

def next_iv():
    return run([NX])[:16]

def enc_first_block(raw_plain: bytes):
    o = run([ENC], raw_plain)
    return o[:16], o[16:32]

def recover():
    secret = bytearray()
    for i in range(1,17):
        k = 16 - i
        iv_real = next_iv()
        iv_used_real, c1_real = enc_first_block(iv_real[:k] + secret)
        found = False
        for g in range(256):
            iv_g = next_iv()
            p1 = bytearray(16)
            p1[:k] = iv_g[:k]
            for idx in range(len(secret)):
                j = k + idx
                p1[j] = iv_g[j] ^ iv_real[j] ^ secret[idx]
            p1[15] = g
            iv_used, c1 = enc_first_block(bytes(p1))
            if c1 == c1_real:
                s = iv_real[15] ^ iv_g[15] ^ g
                secret.append(s)
                print(f"[+] byte {i:2d} = {s:02x}    secret_so_far = {secret.hex()}")
                found = True
                break
        if not found:
            raise RuntimeError(f"match not found at byte {i}")
    print("\nSECRET (hex)  =", secret.hex())
    try:
        print("SECRET (ascii)= ", secret.decode("utf-8"))
    except:
        pass

if __name__ == "__main__":
    recover()
