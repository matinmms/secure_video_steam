
"""
LFSR-based stream cipher.

Polynomial:
    x^16 + x^14 + x^13 + x^11 + 1

Output:
    The least significant bit of the state.

Packing:
    The first generated bit is stored as the MSB
    of the first output byte.
"""

MAX_SEED = 0xFFFF
LFSR_PERIOD_BITS = 0xFFFF


def _validate_seed(seed):
    """Validate that the seed is a non-zero 16-bit integer."""
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")

    if not 1 <= seed <= MAX_SEED:
        raise ValueError("seed must be between 1 and 65535")


def _next_bit(state):
    """
    Generate one output bit and calculate the next LFSR state.

    Returns:
        (output_bit, next_state)
    """
    if not isinstance(state, int) or isinstance(state, bool):
        raise TypeError("state must be an integer")

    if not 1 <= state <= MAX_SEED:
        raise ValueError("state must be a non-zero 16-bit integer")

    # Output is the least significant bit.
    output_bit = state & 1

    # Feedback taps: bits 0, 2, 3, and 5.
    feedback = (
        ((state >> 0) & 1)
        ^ ((state >> 2) & 1)
        ^ ((state >> 3) & 1)
        ^ ((state >> 5) & 1)
    )

    # Shift right and insert feedback at bit 15.
    next_state = (state >> 1) | (feedback << 15)

    return output_bit, next_state


def keystream(length, seed, offset=0):
    """
    Generate a byte sequence from the LFSR.

    Args:
        length: Number of bytes to generate.
        seed: Initial 16-bit non-zero state.
        offset: Number of keystream bytes to skip.

    Returns:
        bytes: Generated keystream.
    """
    _validate_seed(seed)

    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length must be an integer")

    if length < 0:
        raise ValueError("length cannot be negative")

    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError("offset must be an integer")

    if offset < 0:
        raise ValueError("offset cannot be negative")

    state = seed

    # Skip offset bytes (8 bits per byte).
    bits_to_skip = offset * 8

    for _ in range(bits_to_skip):
        _, state = _next_bit(state)

    result = bytearray()

    # Generate 8 bits for every output byte.
    for _ in range(length):
        byte_value = 0

        for bit_position in range(7, -1, -1):
            output_bit, state = _next_bit(state)
            byte_value |= output_bit << bit_position

        result.append(byte_value)

    return bytes(result)


def xor_bytes(data, seed, offset=0):
    """
    Encrypt or decrypt data using the LFSR keystream.

    XOR is symmetric:
        plaintext XOR keystream = ciphertext
        ciphertext XOR keystream = plaintext
    """
    _validate_seed(seed)

    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError("offset must be an integer")

    if offset < 0:
        raise ValueError("offset cannot be negative")

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")

    data = bytes(data)

    key = keystream(
        length=len(data),
        seed=seed,
        offset=offset
    )

    return bytes(
        data_byte ^ key_byte
        for data_byte, key_byte in zip(data, key)
    )
