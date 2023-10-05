import hashlib


class Sha3Ctx:
    def __init__(self, mdlen):
        self.stateB = [0] * 200
        self.stateQ = [0] * 25
        self.mdlen = mdlen
        self.rsiz = 200 - 2 * mdlen
        self.pt = 0

keccakf_rndc = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

keccakf_rotc = [1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44]

keccakf_piln = [10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1]

keccakf_round = 24

def sha3keccakf(st):
    t = 0
    t = [0] * 5
    bc = [0] * 5

    for r in range(keccakf_round):
        # Theta
        for i in range(5):
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20]

        for i in range(5):
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63))
            for j in range(0, 25, 5):
                st[j+i] ^= t

        # Rho Pi
        t = st[1]
        for i in range(24):
            j = keccakf_piln[i]
            bc[0] = st[j]
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]))
            t = bc[0]

        # Chi
        for j in range(0, 25, 5):
            for i in range(5):
                bc[i] = st[j + i]
            for i in range(5):
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5]

        # Iota
        st[0] ^= keccakf_rndc[r]


def sha3update(ctx, data):
    j = ctx.pt
    for i in range(len(data)):
        ctx.stateB[j] ^= ord(data[i])
        j += 1
        if j >= ctx.rsiz:
            sha3keccakf(ctx.stateQ)
            j = 0

    ctx.pt = j

def sha3final(md, ctx):
    ctx.stateB[ctx.pt] ^= 0x06
    ctx.stateB[ctx.rsiz - 1] ^= 0x80
    sha3keccakf(ctx.stateQ)

    for i in range(ctx.mdlen):
        md[i] = ctx.stateB[i]


# sha3 implementation in python
def sha3(data, mdlen):
    ctx = Sha3Ctx(mdlen)
    md = [0] * mdlen

    sha3update(ctx, data)
    sha3final(md, ctx)

    return md


if __name__ == "__main__":
    message = "Hello, SHA-3!".encode("utf-8")
    hash = sha3(message, 32)

    # Convert the bytes hash to a hexadecimal string
    hash_hex = ''.join(format(byte, '02x') for byte in hash)

    # Compute the SHA-3 hashes
    sha3_hash1 = hashlib.sha3_
    print("my SHA-3-256 hash is:", hash_hex)
    print("sha3_256 hash is:", sha3_hash1)

