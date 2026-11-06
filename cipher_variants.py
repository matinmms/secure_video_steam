
"""
cipher_variants.py
==================

Alternative stream-cipher generators:
1. NLFSR: nonlinear feedback shift register
2. Geffe: combination of three LFSRs
"""

from stream_cipher import LFSR_PERIOD_BITS, MAX_SEED, _next_bit


DEFAULT_GEFFE_SEEDS = (0xACE1, 0xBEEF, 0x1234)


def _validate_length(length):
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 0:
        raise ValueError("length must be non-negative")


def _validate_offset(offset):
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    if offset < 0:
        raise ValueError("offset must be non-negative")


def _validate_seed(seed):
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("seed must be an integer")
    if not 1 <= seed <= MAX_SEED:
        raise ValueError(f"seed must be between 1 and {MAX_SEED}")


def _validate_seeds(seeds):
    if not isinstance(seeds, (tuple, list)):
        raise TypeError("seeds must be a tuple or list")

    if len(seeds) != 3:
        raise ValueError("exactly three seeds are required")

    for seed in seeds:
        _validate_seed(seed)


def _nlfsr_next_bit(state):
    """
    Generate one bit using the nonlinear feedback rule.

    Output:
        Least significant bit (bit 0)

    Feedback:
        bit 0 XOR bit 2 XOR bit 3 XOR bit 5
        XOR (bit 1 AND bit 7)
    """
    output_bit = state & 1

    linear_feedback = (
        ((state >> 0) & 1)
        ^ ((state >> 2) & 1)
        ^ ((state >> 3) & 1)
        ^ ((state >> 5) & 1)
    )

    nonlinear_feedback = (
        ((state >> 1) & 1)
        & ((state >> 7) & 1)
    )

    feedback = linear_feedback ^ nonlinear_feedback

    next_state = (state >> 1) | (feedback << 15)

    return output_bit, next_state


def nlfsr_keystream(length, seed, offset=0):
    """
    Generate keystream bytes using the NLFSR variant.

    The first generated bit is placed in the MSB of the first byte.
    Offset is measured in bytes.
    """
    _validate_length(length)
    _validate_seed(seed)
    _validate_offset(offset)

    state = seed

    # Skip the requested number of bytes.
    for _ in range(offset * 8):
        _, state = _nlfsr_next_bit(state)

    result = bytearray()

    for _ in range(length):
        value = 0

        for bit_position in range(8):
            output_bit, state = _nlfsr_next_bit(state)
            value = (value << 1) | output_bit

        result.append(value)

    return bytes(result)


def geffe_keystream(length, seeds=DEFAULT_GEFFE_SEEDS, offset=0):
    """
    Generate keystream bytes using the Geffe generator.

    Three LFSRs are combined using:

        output = (x AND y) XOR ((1 XOR x) AND z)

    The first generated bit is placed in the MSB of the first byte.
    Offset is measured in bytes.
    """
    _validate_length(length)
    _validate_seeds(seeds)
    _validate_offset(offset)

    state_x, state_y, state_z = seeds

    # Skip the requested number of bytes in all three registers.
    for _ in range(offset * 8):
        _, state_x = _next_bit(state_x)
        _, state_y = _next_bit(state_y)
        _, state_z = _next_bit(state_z)

    result = bytearray()

    for _ in range(length):
        value = 0

        for bit_position in range(8):
            x, state_x = _next_bit(state_x)
            y, state_y = _next_bit(state_y)
            z, state_z = _next_bit(state_z)

            output_bit = (x & y) ^ ((1 ^ x) & z)

            value = (value << 1) | output_bit

        result.append(value)

    return bytes(result)
