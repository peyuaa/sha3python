def rol64(a, n):
    """
        Rotate a 64-bit integer left by 'n' bits.

        Parameters:
            a (int): The 64-bit integer to be rotated.
            n (int): The number of bits to rotate 'a' to the left.

        Returns:
            int: The result of rotating 'a' left by 'n' bits.

        Example:
            >>> rol64(4, 2)
            16
        """

    # Ensure 'n' is within the range [0, 63] to handle large rotations
    n = n % 64

    # Initialize the result to 0
    result = 0

    # Iterate over 64 bits of 'a' and perform left rotation
    for i in range(64):
        # Get the i-th bit of 'a'
        bit_at_i = (a >> i) & 1

        # Calculate the new position after left rotation
        new_position = (i + n) % 64

        # Set the bit in the result at the new position
        result |= (bit_at_i << new_position)

    # Return the result, which is 'a' left-rotated by 'n' bits
    return result


def theta(lanes):
    c = [0] * 5
    for x in range(5):
        for y in range(5):
            c[x] ^= lanes[x][y]

    d = [0] * 5
    for x in range(5):
        d[x] = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1)

    for x in range(5):
        for y in range(5):
            lanes[x][y] ^= d[x]


def rho_and_pi(lanes):
    (x, y) = (1, 0)
    current = lanes[x][y]
    for t in range(24):
        (x, y) = (y, (2 * x + 3 * y) % 5)
        (current, lanes[x][y]) = (lanes[x][y], rol64(current, (t + 1) * (t + 2) // 2))


def chi(lanes):
    for y in range(5):
        t = [lanes[x][y] for x in range(5)]
        for x in range(5):
            lanes[x][y] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5])


def iota(lanes, r):
    for j in range(7):
        r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
        if r & 2:
            lanes[0][0] = lanes[0][0] ^ (1 << ((1 << j) - 1))
    return r


def keccak_f1600on_lanes(lanes):
    """
        Apply the Keccak-f[1600] permutation to a state represented as lanes.

        This function applies the Keccak-f[1600] permutation to a state represented as lanes,
        including the θ, ρ, π, χ, and ι rounds.

        Parameters:
            lanes (list[list[int]]): A list of 5x5 lanes, each containing a 64-bit integer.

        Returns:
            list[list[int]]: The transformed state represented as lanes after applying Keccak-f[1600].

        Example:
            >>> initial_state = [[0] * 5 for _ in range(5)]  # Initialize an empty state
            >>> transformed_state = keccak_f1600on_lanes(initial_state)

        Note:
            This function operates directly on the 'lanes' list and modifies it in place.

        See Also:
            - The Keccak-f[1600] permutation details in FIPS 202.
        """
    r = 1

    # Apply 24 rounds of the Keccak-f[1600] permutation
    for rnd in range(24):
        # θ
        theta(lanes)

        # ρ and π
        rho_and_pi(lanes)

        # χ
        chi(lanes)

        # ι transformation and update round constant
        r = iota(lanes, r)
    return lanes


def load64(b):
    """
        Load a 64-bit integer from a bytearray.

        This function takes a bytearray 'b' containing 8 bytes and converts it
        into a 64-bit integer by combining the bytes in little-endian order.

        Parameters:
            b (bytearray): A bytearray containing 8 bytes of data.

        Returns:
            int: A 64-bit integer obtained by combining the bytes in little-endian order.

        Example:
            >>> load64(bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
            578437695752307201
        """

    # Initialize the result to 0
    result = 0

    # Iterate over 8 bytes in little-endian order and combine them into a 64-bit integer
    for i in range(8):
        # Extract the i-th byte from the bytearray 'b' and shift it to its position
        byte = b[i]

        # Combine the byte with the result using bitwise OR and left shift
        result |= (byte << (8 * i))

    # Return the 64-bit integer obtained by combining the bytes in little-endian order
    return result


def store64(a):
    """
        Convert a 64-bit integer to a bytearray.

        This function takes a 64-bit integer 'a' and converts it into an array
        containing 8 bytes in little-endian order.

        Parameters:
            a (int): A 64-bit integer to be converted into a bytearray.

        Returns:
            bytearray: An array containing 8 bytes representing the value of 'a' in little-endian order.

        Example:
            >>> store64(578437695752307201)
            [1, 2, 3, 4, 5, 6, 7, 8]
        """
    result = []

    # Iterate over 8 bytes
    for i in range(8):
        # Extract the i-th byte from 'a' using bitwise shifting and masking
        byte = (a >> (8 * i)) & 0xFF

        # Append the extracted byte to the result list
        result.append(byte)
    return result


def keccak_f1600(state):
    """
        Apply the Keccak-f[1600] permutation to the state.

        This function takes a state bytearray and applies the Keccak-f[1600] permutation
        to it, which consists of a series of transformations, including θ, ρ, π, χ, and ι.

        Parameters:
            state (bytearray): The state bytearray to be transformed.

        Returns:
            bytearray: The transformed state bytearray after applying Keccak-f[1600].

        Example:
            >>> initial_state = bytearray([0] * 200)
            >>> transformed_state = keccak_f1600(initial_state)

        Note:
            This function operates directly on the 'state' bytearray and modifies it in place.
        """

    # Initialize an empty list 'lanes' to hold the 64-bit lanes of the state matrix
    lanes = []

    # Iterate over the rows and columns of the state matrix
    for x in range(5):
        row = []  # Initialize a row to hold lanes for each column
        for y in range(5):
            # Calculate the start and end indices for extracting 8 bytes (64 bits) from the state
            start = 8 * (x + 5 * y)
            end = 8 * (x + 5 * y) + 8

            # Extract a 64-bit lane from the state and append it to the row
            lane = load64(state[start:end])
            row.append(lane)

        # Append the row of lanes to the 'lanes' list
        lanes.append(row)

    # Apply the Keccak-f[1600] permutation on the 'lanes'
    lanes = keccak_f1600on_lanes(lanes)

    # Create a new 'state' bytearray with a size of 200 bytes
    state = bytearray(200)

    # Copy the transformed 'lanes' back into the 'state' bytearray
    for x in range(5):
        for y in range(5):
            # Extract a lane from 'lanes' and store it in the 'state'
            state[8 * (x + 5 * y):8 * (x + 5 * y) + 8] = store64(lanes[x][y])

    # Return the updated 'state' bytearray after Keccak-f[1600] permutation
    return state


def keccak(rate, capacity, input_bytes, delimiter, output_byte_len):
    """
        Compute a Keccak sponge-based hash or SHAKE hash.

        This function applies the Keccak sponge construction to absorb input bytes,
        perform padding, and squeeze out an output hash of the specified length.

        Parameters:
            rate (int): The rate of the sponge construction in bits (e.g., 1344 for SHAKE128).
            capacity (int): The capacity of the sponge construction in bits (e.g., 256 for SHAKE128).
            input_bytes (bytes): The input bytes to be hashed.
            delimiter (int): A delimiter value used in padding.
            output_byte_len (int): The desired length of the output hash in bytes.

        Returns:
            bytearray: The computed hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = keccak(1344, 256, input_data, 0x1F, 64)

        Note:
            - This function can be used to compute both Keccak hash and SHAKE hash.
            - The 'rate' and 'capacity' parameters determine the security level and hash length.
            - Padding is automatically applied based on the 'delimiter'.
        """

    # Initialize an empty bytearray to store the output hash
    output_bytes = bytearray()

    # Initialize the state bytearray with 200 bytes of zeros
    state = bytearray([0 for _ in range(200)])

    # Calculate the rate in bytes
    rate_in_bytes = rate // 8

    # Initialize the block size to 0
    block_size = 0

    # Validate that the rate and capacity values meet Keccak requirements
    if ((rate + capacity) != 1600) or ((rate % 8) != 0):
        return

    # Initialize the input offset to 0
    input_offset = 0

    # === Absorb all the input blocks ===
    while input_offset < len(input_bytes):
        # Determine the size of the current block to be absorbed
        block_size = min(len(input_bytes) - input_offset, rate_in_bytes)

        # XOR the current block of input bytes with the state
        for i in range(block_size):
            state[i] = state[i] ^ input_bytes[i + input_offset]

        # Update the input offset
        input_offset = input_offset + block_size

        # If a full block is processed, apply Keccak-f[1600] permutation
        if block_size == rate_in_bytes:
            state = keccak_f1600(state)
            block_size = 0

    # === Do the padding and switch to the squeezing phase ===
    # XOR the delimiter with the last byte of the current block
    state[block_size] = state[block_size] ^ delimiter

    # Check if the delimiter's MSB (most significant bit) is set, and if block_size is one less than the rate_in_bytes
    if ((delimiter & 0x80) != 0) and (block_size == (rate_in_bytes - 1)):
        state = keccak_f1600(state)

    # Set the last byte of the current block's MSB to 1
    state[rate_in_bytes - 1] = state[rate_in_bytes - 1] ^ 0x80

    # Apply Keccak-f[1600] one more time
    state = keccak_f1600(state)

    # === Squeeze out all the output blocks ===
    while output_byte_len > 0:
        # Determine the size of the current block to be squeezed
        block_size = min(output_byte_len, rate_in_bytes)

        # Append the block of bytes to the output
        output_bytes = output_bytes + state[0:block_size]

        # Update the remaining output length
        output_byte_len = output_byte_len - block_size

        # If there's more output to generate, apply Keccak-f[1600] again
        if output_byte_len > 0:
            state = keccak_f1600(state)

    # Return the computed output hash
    return output_bytes


def shake128(input_bytes, output_byte_len):
    """
        Compute a SHAKE128 hash.

        This function computes a SHAKE128 hash using the Keccak sponge construction.
        SHAKE128 produces a variable-length output hash of the specified length.

        Parameters:
            input_bytes (bytes): The input bytes to be hashed.
            output_byte_len (int): The desired length of the output hash in bytes.

        Returns:
            bytearray: The computed SHAKE128 hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = shake128(input_data, 64)

        Note:
            - SHAKE128 is an SHA-3 derived hash that produces variable-length output.
            - The 'output_byte_len' parameter determines the length of the hash.
            - The function internally uses Keccak with a rate of 1344 and a capacity of 256.
        """
    # Delegate to the 'keccak' function with specific parameters
    return keccak(1344, 256, input_bytes, 0x1F, output_byte_len)


def shake256(input_bytes, output_byte_len):
    """
        Compute a SHAKE256 hash.

        This function computes a SHAKE256 hash using the Keccak sponge construction.
        SHAKE256 produces a variable-length output hash of the specified length.

        Parameters:
            input_bytes (bytes): The input bytes to be hashed.
            output_byte_len (int): The desired length of the output hash in bytes.

        Returns:
            bytearray: The computed SHAKE256 hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = shake256(input_data, 64)

        Note:
            - SHAKE256 is an SHA-3 derived hash that produces variable-length output.
            - The 'output_byte_len' parameter determines the length of the hash.
            - The function internally uses Keccak with a rate of 1088 and a capacity of 512.
        """
    # Delegate to the 'keccak' function with specific parameters
    return keccak(1088, 512, input_bytes, 0x1F, output_byte_len)


def sha3_224(input_bytes):
    """
        Compute a SHA3-224 hash.

        This function computes a SHA3-224 hash using the Keccak sponge construction.
        SHA3-224 produces a fixed-length output hash of 224 bits (28 bytes).

        Parameters:
            input_bytes (bytes): The input bytes to be hashed.

        Returns:
            bytearray: The computed SHA3-224 hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = sha3_224(input_data)

        Note:
            - SHA3-224 is one of the SHA-3 hash functions with a fixed output length of 224 bits.
            - The function internally uses Keccak with a rate of 1152 and a capacity of 448.
        """
    return keccak(1152, 448, input_bytes, 0x06, 224 // 8)


def sha3_256(input_bytes):
    """
        Compute a SHA3-256 hash.

        This function computes a SHA3-256 hash using the Keccak sponge construction.
        SHA3-256 produces a fixed-length output hash of 256 bits (32 bytes).

        Parameters:
            input_bytes (bytes): The input bytes to be hashed.

        Returns:
            bytearray: The computed SHA3-256 hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = sha3_256(input_data)

        Note:
            - SHA3-256 is one of the SHA-3 hash functions with a fixed output length of 256 bits.
            - The function internally uses Keccak with a rate of 1088 and a capacity of 512.
        """
    # Delegate to the 'keccak' function with specific parameters for SHA3-256
    return keccak(1088, 512, input_bytes, 0x06, 256 // 8)


def sha3_384(input_bytes):
    """
        Compute a SHA3-384 hash.

        This function computes a SHA3-384 hash using the Keccak sponge construction.
        SHA3-384 produces a fixed-length output hash of 384 bits (48 bytes).

        Parameters:
            input_bytes (bytes): The input bytes to be hashed.

        Returns:
            bytearray: The computed SHA3-384 hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = sha3_384(input_data)

        Note:
            - SHA3-384 is one of the SHA-3 hash functions with a fixed output length of 384 bits.
            - The function internally uses Keccak with a rate of 832 and a capacity of 768.
        """
    # Delegate to the 'keccak' function with specific parameters for SHA3-384
    return keccak(832, 768, input_bytes, 0x06, 384 // 8)


def sha3_512(input_bytes):
    """
        Compute a SHA3-512 hash.

        This function computes a SHA3-512 hash using the Keccak sponge construction.
        SHA3-512 produces a fixed-length output hash of 512 bits (64 bytes).

        Parameters:
            input_bytes (bytes): The input bytes to be hashed.

        Returns:
            bytearray: The computed SHA3-512 hash as a bytearray.

        Example:
            >>> input_data = b"Hello, World!"
            >>> hash_output = sha3_512(input_data)

        Note:
            - SHA3-512 is one of the SHA-3 hash functions with a fixed output length of 512 bits.
            - The function internally uses Keccak with a rate of 576 and a capacity of 1024.
        """
    # Delegate to the 'keccak' function with specific parameters for SHA3-512
    return keccak(576, 1024, input_bytes, 0x06, 512 // 8)


digest = sha3_512(b"TI PIDOR.")
hex_representation = ''.join(['{:02x}'.format(b) for b in digest])
print(hex_representation)
