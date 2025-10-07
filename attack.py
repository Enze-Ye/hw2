import subprocess, sys

NX  = "/project/web-classes/Fall-2025/csci5471/hw2/next_iv"
ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out,_ = p.communicate(data)
    return out

def next_iv():
    return run([NX])[:16]

def enc_once(raw_plain: bytes):
    o = run([ENC], raw_plain)
    return o[:16], o[16:32]  

def fetch_with_iv(payload_builder):
    """反复：peek 当前IV → 立刻 encrypt；直到 encrypt 返回的 IV 与 peek 一致"""
    while True:
        iv = next_iv()
        iv_used, c1 = enc_once(payload_builder(iv))
        if iv_used == iv:
            return iv, c1

def recover():
    secret = bytearray()

    for i in range(1, 17):               
        k = 16 - i

        while True:                      
            iv_real, c1_real = fetch_with_iv(lambda iv: (iv[:k] + secret))

            found = False
            g = 0
            while g < 256:
                def build_tbl(iv_g, g=g, iv_real=iv_real, secret=secret, k=k):
                    p1 = bytearray(16)
                    p1[:k] = iv_g[:k]
                    for idx in range(len(secret)):    
                        j = k + idx
                        p1[j] = iv_g[j] ^ iv_real[j] ^ secret[idx]
                    p1[15] = g                         
                    return bytes(p1)

                iv_g, c1 = fetch_with_iv(build_tbl)

                if c1 == c1_real:
                    s = iv_real[15] ^ iv_g[15] ^ g
                    secret.append(s)
                    print(f"[+] byte {i:2d} = {s:02x}    secret_so_far = {secret.hex()}")
                    sys.stdout.flush()
                    found = True
                    break

                g += 1

            if found:
                break

    print("\nSECRET (hex)  =", secret.hex())
    try:
        print("SECRET (ascii)= ", secret.decode("utf-8"))
    except:
        pass

if __name__ == "__main__":
    recover()
