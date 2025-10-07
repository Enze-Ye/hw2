import subprocess, binascii

NX  = "/project/web-classes/Fall-2025/csci5471/hw2/next_iv"
ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out,_ = p.communicate(data)
    return out

def next_iv():
    return run([NX])           

def enc_first_block(plain: bytes) -> bytes:
    out = run([ENC], plain)          
    return out[16:32]                

def recover():
    secret = bytearray()
    for i in range(1, 17):
        k = 16 - i
        iv0 = next_iv()
        iv1 = next_iv()

        table = {}
        for g in range(256):
            p1 = bytearray(16)
            p1[:k] = iv0[:k]
            for idx in range(len(secret)):
                j = k + idx
                p1[j] = iv0[j] ^ iv1[j] ^ secret[idx]
            p1[15] = g
            c1 = enc_first_block(bytes.fromhex(binascii.hexlify(p1).decode()))
            table[c1] = g

        real_prefix = iv1[:k] + secret
        c1_real = enc_first_block(real_prefix)

        gstar = table.get(c1_real)
        if gstar is None:
            raise RuntimeError(f"match not found at byte {i}")
        secret.append(iv1[15] ^ iv0[15] ^ gstar)
        print(f"[+] byte {i} = {secret[-1]:02x}    secret_so_far = {secret.hex()}")

    print("\nSECRET (hex)  =", secret.hex())
    try:
        print("SECRET (ascii)= ", secret.decode("utf-8"))
    except:
        pass

if __name__ == "__main__":
    recover()
