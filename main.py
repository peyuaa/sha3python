def rol64(a, n):
    n = n % 64  # Ensure n is within the range [0, 63]
    result = 0
    for i in range(64):
        bit_at_i = (a >> i) & 1  # Get the i-th bit of 'a'
        new_position = (i + n) % 64  # Calculate the new position after rotation
        result |= (bit_at_i << new_position)  # Set the bit in the result
    return result


def keccak_f1600on_lanes(lanes):
    r = 1
    for rnd in range(24):
        # θ
        c = [0] * 5  # Initialize c as a list of zeros with length 5
        for x in range(5):
            for y in range(5):
                c[x] ^= lanes[x][y]

        d = [0] * 5  # Initialize d as a list of zeros with length 5
        for x in range(5):
            d[x] = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1)

        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= d[x]

        # ρ and π
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(24):
            (x, y) = (y, (2 * x + 3 * y) % 5)
            (current, lanes[x][y]) = (lanes[x][y], rol64(current, (t + 1) * (t + 2) // 2))
        # χ
        for y in range(5):
            t = []
            for x in range(5):
                t.append(lanes[x][y])

            for x in range(5):
                lanes[x][y] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5])
        # ι
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                lanes[0][0] = lanes[0][0] ^ (1 << ((1 << j) - 1))
    return lanes


def load64(b):
    result = 0
    for i in range(8):
        result |= (b[i] << (8 * i))
    return result


def store64(a):
    result = []
    for i in range(8):
        byte = (a >> (8 * i)) & 0xFF
        result.append(byte)
    return result


def keccak_f1600(state):
    lanes = []
    for x in range(5):
        row = []
        for y in range(5):
            start = 8 * (x + 5 * y)
            end = 8 * (x + 5 * y) + 8
            lane = load64(state[start:end])
            row.append(lane)
        lanes.append(row)

    lanes = keccak_f1600on_lanes(lanes)
    state = bytearray(200)
    for x in range(5):
        for y in range(5):
            state[8 * (x + 5 * y):8 * (x + 5 * y) + 8] = store64(lanes[x][y])
    return state


def keccak(rate, capacity, input_bytes, delimiter, output_byte_len):
    output_bytes = bytearray()
    state = bytearray([0 for _ in range(200)])
    rate_in_bytes = rate // 8
    block_size = 0
    if ((rate + capacity) != 1600) or ((rate % 8) != 0):
        return
    input_offset = 0
    # === Absorb all the input blocks ===
    while input_offset < len(input_bytes):
        block_size = min(len(input_bytes) - input_offset, rate_in_bytes)
        for i in range(block_size):
            state[i] = state[i] ^ input_bytes[i + input_offset]
        input_offset = input_offset + block_size
        if block_size == rate_in_bytes:
            state = keccak_f1600(state)
            block_size = 0
    # === Do the padding and switch to the squeezing phase ===
    state[block_size] = state[block_size] ^ delimiter
    if ((delimiter & 0x80) != 0) and (block_size == (rate_in_bytes - 1)):
        state = keccak_f1600(state)
    state[rate_in_bytes - 1] = state[rate_in_bytes - 1] ^ 0x80
    state = keccak_f1600(state)
    # === Squeeze out all the output blocks ===
    while output_byte_len > 0:
        block_size = min(output_byte_len, rate_in_bytes)
        output_bytes = output_bytes + state[0:block_size]
        output_byte_len = output_byte_len - block_size
        if output_byte_len > 0:
            state = keccak_f1600(state)
    return output_bytes


def shake128(input_bytes, output_byte_len):
    return keccak(1344, 256, input_bytes, 0x1F, output_byte_len)


def shake256(input_bytes, output_byte_len):
    return keccak(1088, 512, input_bytes, 0x1F, output_byte_len)


def sha3_224(input_bytes):
    return keccak(1152, 448, input_bytes, 0x06, 224 // 8)


def sha3_256(input_bytes):
    return keccak(1088, 512, input_bytes, 0x06, 256 // 8)


def sha3_384(input_bytes):
    return keccak(832, 768, input_bytes, 0x06, 384 // 8)


def sha3_512(input_bytes):
    return keccak(576, 1024, input_bytes, 0x06, 512 // 8)


digest = sha3_512(b"TI PIDOR.")
hex_representation = ''.join(['{:02x}'.format(b) for b in digest])
print(hex_representation)
