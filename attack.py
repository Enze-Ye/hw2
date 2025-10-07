import subprocess, binascii

NX = "/project/web-classes/Fall-2025/csci5471/hw2/next_iv"
ENC = "/project/web-classes/Fall-2025/csci5471/hw2/encrypt"

def run(cmd, data=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate(data)
    return out

def next_iv():
    return run([NX])

def encrypt_block(plain: bytes):
    out = run([ENC], plain)
    return out[16:32]  

def recover_secret():
    secret = bytearray()

    for i in range(16):
        iv1 = next_iv()
        iv2 = next_iv()

        if i == 0:
            print("IV1:", binascii.hexlify(iv1))
            print("IV2:", binascii.hexlify(iv2))

        table = {}
        for g in range(256):
            prefix = b"\x00" * (15 - i) + bytes(secret) + bytes([g])
            c = encrypt_block(prefix)
            table[c] = g

        c_real = encrypt_block(b"\x00" * (15 - i))
        if c_real in table:
            secret.append(table[c_real])
            print(f"[+] byte {i+1} found:", table[c_real])
        else:
            raise RuntimeError(f"match not found at byte {i+1}")

    print("Recovered secret:", secret.hex())

if __name__ == "__main__":
    recover_secret()
