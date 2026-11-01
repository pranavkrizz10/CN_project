"""
================================================================================
 hamming.py  --  ERROR CONTROL for the Data Link Layer
================================================================================

WHAT THIS MODULE DOES
---------------------
The Data Link Layer is responsible for *error control*: making sure that the
bits that leave the sender are the same bits that arrive at the receiver, even
though the physical medium occasionally flips a bit (noise, interference...).

This module implements a **Hamming code** -- a classic Forward Error Correction
(FEC) technique.  A Hamming code adds a small number of redundant "parity" bits
to the data.  Using those parity bits the receiver can:

    * DETECT  that an error happened, and
    * CORRECT a single-bit error all by itself (no retransmission needed).

On top of the plain Hamming code we add ONE extra "overall" parity bit.  This
upgrades the code to **SECDED**:
        Single Error Correction, Double Error Detection.

    - 0 bit flips  -> reported as NO_ERROR
    - 1 bit flip   -> automatically CORRECTED
    - 2 bit flips  -> DETECTED as a DOUBLE_ERROR (cannot be corrected, so the
                      frame is dropped and Go-Back-N will retransmit it later)

HOW A HAMMING CODE IS LAID OUT
------------------------------
Bit positions are numbered starting at 1.  Every position that is a power of two
(1, 2, 4, 8, ...) holds a PARITY bit.  All the other positions hold DATA bits.

    position : 1  2  3  4  5  6  7
    role     : P1 P2 D1 P4 D2 D3 D4      <-- this is the famous Hamming(7,4)

Each parity bit Pk (at position k) checks every position whose binary index has
the same bit set as k.  Example for Hamming(7,4):

    P1 (pos 1) checks positions 1,3,5,7   (all odd positions)
    P2 (pos 2) checks positions 2,3,6,7
    P4 (pos 4) checks positions 4,5,6,7

When decoding, the receiver recomputes each parity check.  The failing checks,
read together as a binary number, point EXACTLY at the position of the flipped
bit -- that number is called the "syndrome".  A syndrome of 0 means all checks
passed.

This file is intentionally written as a *general* Hamming coder: it works for
any number of data bits, not just 4.  The rest of the project feeds it 4-bit
nibbles, so each nibble becomes an 8-bit codeword (7 Hamming bits + 1 overall
parity bit), which is convenient because it is exactly one byte.
================================================================================
"""

from enum import Enum
from typing import List, Tuple


# ------------------------------------------------------------------------------
# A small, readable status code so the caller knows what the decoder concluded.
# ------------------------------------------------------------------------------
class HammingStatus(Enum):
    NO_ERROR     = "NO_ERROR"       # codeword arrived clean
    CORRECTED    = "CORRECTED"      # exactly one bit was flipped and we fixed it
    DOUBLE_ERROR = "DOUBLE_ERROR"   # two bits were flipped -> detected, not fixable


# ------------------------------------------------------------------------------
# Tiny bit helpers (bytes <-> list-of-bits).  Keeping these explicit makes the
# data flow very easy to follow in the console output.
# ------------------------------------------------------------------------------
def _is_power_of_two(x: int) -> bool:
    """Return True if x is 1, 2, 4, 8, 16, ...  (i.e. a parity-bit position)."""
    return x != 0 and (x & (x - 1)) == 0


def byte_to_bits(byte_value: int) -> List[int]:
    """Convert one byte (0-255) into a list of 8 bits, most-significant first."""
    return [(byte_value >> (7 - i)) & 1 for i in range(8)]


def bits_to_byte(bits: List[int]) -> int:
    """Convert a list of 8 bits (MSB first) back into a single byte value."""
    value = 0
    for b in bits:
        value = (value << 1) | (b & 1)
    return value


def nibble_to_bits(nibble_value: int) -> List[int]:
    """Convert a 4-bit nibble (0-15) into a list of 4 bits, MSB first."""
    return [(nibble_value >> (3 - i)) & 1 for i in range(4)]


def bits_to_nibble(bits: List[int]) -> int:
    """Convert a list of 4 bits (MSB first) back into a nibble value (0-15)."""
    value = 0
    for b in bits:
        value = (value << 1) | (b & 1)
    return value


# ------------------------------------------------------------------------------
# CORE ENCODER
# ------------------------------------------------------------------------------
def hamming_encode(data_bits: List[int]) -> List[int]:
    """
    Encode a list of raw data bits into a SECDED Hamming codeword.

    Returns a NEW list of bits laid out as:

        [ overall_parity , c1 , c2 , c3 , ... , cn ]

    where c1..cn is the ordinary Hamming codeword (data interleaved with parity
    bits at power-of-two positions) and overall_parity is the extra bit that
    gives us double-error *detection*.
    """
    m = len(data_bits)                       # number of data bits we must carry

    # Step 1: work out how many parity bits (r) we need.
    # The rule is: 2^r must be big enough to number every position, i.e.
    #   2^r >= m + r + 1   (the +1 is because position 0 is unused / "no error").
    r = 0
    while (2 ** r) < (m + r + 1):
        r += 1

    n = m + r                                # total length of the Hamming part

    # Step 2: place the data bits into the non-power-of-two positions.
    # We use a 1-indexed list, so index 0 is just a throw-away placeholder.
    code = [0] * (n + 1)
    data_cursor = 0
    for pos in range(1, n + 1):
        if not _is_power_of_two(pos):        # data goes everywhere except P positions
            code[pos] = data_bits[data_cursor]
            data_cursor += 1

    # Step 3: compute each parity bit.  Parity position p (1,2,4,8,...) covers
    # every position whose index ANDed with p is non-zero.  We use EVEN parity:
    # choose the parity bit so the total number of 1s in its group is even.
    parity_pos = 1
    while parity_pos <= n:
        xor_sum = 0
        for pos in range(1, n + 1):
            if pos != parity_pos and (pos & parity_pos):
                xor_sum ^= code[pos]
        code[parity_pos] = xor_sum           # set parity so the group is even
        parity_pos <<= 1                     # next power of two

    # Step 4: compute the single OVERALL parity bit over the whole Hamming part.
    # This is what turns plain Hamming (correct 1) into SECDED (correct 1 /
    # detect 2).  Again even parity.
    overall = 0
    for pos in range(1, n + 1):
        overall ^= code[pos]

    # Final codeword: overall parity bit first, then the Hamming codeword.
    return [overall] + code[1:]


# ------------------------------------------------------------------------------
# CORE DECODER
# ------------------------------------------------------------------------------
def hamming_decode(received: List[int]) -> Tuple[List[int], HammingStatus, int]:
    """
    Decode (and if possible repair) a SECDED Hamming codeword.

    Input  : the received bit list  [ overall , c1 , c2 , ... , cn ]
    Returns: (data_bits, status, error_position)
        data_bits      -> the recovered DATA bits (parity bits stripped out)
        status         -> NO_ERROR / CORRECTED / DOUBLE_ERROR
        error_position -> 1..n if a Hamming-part bit was corrected,
                          0 if the overall bit was corrected or no error,
                          -1 if a double error was detected (uncorrectable)
    """
    overall_received = received[0]           # the extra overall parity bit
    code = [0] + list(received[1:])          # re-create the 1-indexed Hamming part
    n = len(code) - 1

    # Step 1: recompute the syndrome.  For each parity position we re-run the
    # parity check INCLUDING the parity bit itself.  If a check fails we add that
    # parity position's value into the syndrome.  The syndrome, read as a normal
    # integer, is the position of the flipped bit (or 0 if the checks all pass).
    syndrome = 0
    parity_pos = 1
    while parity_pos <= n:
        xor_sum = 0
        for pos in range(1, n + 1):
            if pos & parity_pos:
                xor_sum ^= code[pos]
        if xor_sum != 0:                     # this parity group is wrong
            syndrome += parity_pos
        parity_pos <<= 1

    # Step 2: recompute the overall parity across EVERYTHING (the overall bit and
    # all Hamming bits).  If the total is 0, an even number of bits are wrong
    # (0 or 2...); if it is 1, an odd number are wrong (1 or 3...).
    overall_calc = overall_received
    for pos in range(1, n + 1):
        overall_calc ^= code[pos]

    # Step 3: the SECDED decision table.
    status = HammingStatus.NO_ERROR
    error_position = 0

    if syndrome == 0 and overall_calc == 0:
        # Both checks happy -> the codeword is clean.
        status = HammingStatus.NO_ERROR
        error_position = 0

    elif overall_calc == 1:
        # Overall parity says an ODD number of bits flipped -> treat as a single
        # (correctable) error.
        if syndrome == 0:
            # The Hamming checks all passed but overall parity failed, so the one
            # flipped bit must be the overall parity bit itself.  Data is fine.
            status = HammingStatus.CORRECTED
            error_position = 0
        else:
            # A normal single-bit error inside the Hamming part: the syndrome is
            # the exact position, so just flip it back.
            code[syndrome] ^= 1
            status = HammingStatus.CORRECTED
            error_position = syndrome

    else:
        # overall_calc == 0 but syndrome != 0 -> an EVEN number of bits (two)
        # flipped.  SECDED can detect this but cannot locate/repair it.
        status = HammingStatus.DOUBLE_ERROR
        error_position = -1

    # Step 4: pull the DATA bits back out of the (possibly repaired) codeword by
    # skipping every power-of-two (parity) position.
    data_bits = [code[pos] for pos in range(1, n + 1) if not _is_power_of_two(pos)]

    return data_bits, status, error_position


# ------------------------------------------------------------------------------
# BYTE-LEVEL CONVENIENCE WRAPPERS
# ------------------------------------------------------------------------------
# The rest of the project works with bytes (frame payloads).  We encode each
# byte as TWO nibbles, and each nibble becomes an 8-bit SECDED codeword (exactly
# one byte).  So every 1 payload byte turns into 2 "coded" bytes on the wire.
# ------------------------------------------------------------------------------
def encode_byte(byte_value: int) -> bytes:
    """Encode one data byte into two SECDED-Hamming codeword bytes."""
    high_nibble = (byte_value >> 4) & 0x0F
    low_nibble = byte_value & 0x0F
    high_code = bits_to_byte(hamming_encode(nibble_to_bits(high_nibble)))
    low_code = bits_to_byte(hamming_encode(nibble_to_bits(low_nibble)))
    return bytes([high_code, low_code])


def encode_bytes(data: bytes) -> bytes:
    """Encode a whole byte string; output is exactly twice as long."""
    out = bytearray()
    for b in data:
        out += encode_byte(b)
    return bytes(out)


def decode_byte(code_bytes: bytes) -> Tuple[int, HammingStatus]:
    """
    Decode two codeword bytes back into one data byte.

    The byte's status is the "worst" of its two nibbles: if either nibble shows a
    DOUBLE_ERROR the byte is DOUBLE_ERROR; else if either was CORRECTED the byte
    is CORRECTED; otherwise NO_ERROR.
    """
    high_bits, high_status, _ = hamming_decode(byte_to_bits(code_bytes[0]))
    low_bits, low_status, _ = hamming_decode(byte_to_bits(code_bytes[1]))

    byte_value = (bits_to_nibble(high_bits) << 4) | bits_to_nibble(low_bits)

    if HammingStatus.DOUBLE_ERROR in (high_status, low_status):
        status = HammingStatus.DOUBLE_ERROR
    elif HammingStatus.CORRECTED in (high_status, low_status):
        status = HammingStatus.CORRECTED
    else:
        status = HammingStatus.NO_ERROR
    return byte_value, status


def decode_bytes(code: bytes) -> Tuple[bytes, HammingStatus, int]:
    """
    Decode a whole coded byte string.

    Returns (data_bytes, overall_status, corrected_count):
        overall_status  -> DOUBLE_ERROR if any byte was uncorrectable,
                           else CORRECTED if any byte needed fixing,
                           else NO_ERROR.
        corrected_count -> how many data bytes had a single-bit error repaired.
    """
    out = bytearray()
    corrected_count = 0
    overall_status = HammingStatus.NO_ERROR

    # Walk the coded stream two bytes (one original byte) at a time.
    for i in range(0, len(code), 2):
        value, status = decode_byte(code[i:i + 2])
        out.append(value)
        if status == HammingStatus.DOUBLE_ERROR:
            overall_status = HammingStatus.DOUBLE_ERROR
        elif status == HammingStatus.CORRECTED:
            corrected_count += 1
            if overall_status == HammingStatus.NO_ERROR:
                overall_status = HammingStatus.CORRECTED

    return bytes(out), overall_status, corrected_count


# ------------------------------------------------------------------------------
# SELF-TEST: run `python3 hamming.py` directly to prove the maths is correct.
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print(" HAMMING CODE  --  SELF TEST  (SECDED: correct 1 bit, detect 2 bits)")
    print("=" * 70)

    # --- Test 1: a clean nibble should decode with NO_ERROR ------------------
    original = [1, 0, 1, 1]
    cw = hamming_encode(original)
    data, st, pos = hamming_decode(cw)
    print(f"\n[1] Clean codeword")
    print(f"    data in   : {original}")
    print(f"    codeword  : {cw}")
    print(f"    data out  : {data}   status={st.value}")
    assert data == original and st == HammingStatus.NO_ERROR

    # --- Test 2: flip ONE bit -> decoder must correct it ---------------------
    corrupted = cw.copy()
    corrupted[4] ^= 1                        # flip some bit
    data, st, pos = hamming_decode(corrupted)
    print(f"\n[2] Single-bit error (flipped index 4)")
    print(f"    received  : {corrupted}")
    print(f"    data out  : {data}   status={st.value}  corrected_pos={pos}")
    assert data == original and st == HammingStatus.CORRECTED

    # --- Test 3: flip TWO bits -> decoder must DETECT a double error ----------
    corrupted2 = cw.copy()
    corrupted2[3] ^= 1
    corrupted2[6] ^= 1
    data, st, pos = hamming_decode(corrupted2)
    print(f"\n[3] Double-bit error (flipped indices 3 and 6)")
    print(f"    received  : {corrupted2}")
    print(f"    status    : {st.value}  (detected, not correctable)")
    assert st == HammingStatus.DOUBLE_ERROR

    # --- Test 4: full byte round trip through every single-bit error ---------
    print(f"\n[4] Byte round-trip with single-bit errors in every position")
    ok = True
    for value in range(256):
        coded = encode_byte(value)
        for bit in range(16):                # 2 bytes = 16 bits to flip
            tampered = bytearray(coded)
            tampered[bit // 8] ^= (1 << (7 - (bit % 8)))
            recovered, status = decode_byte(bytes(tampered))
            if recovered != value or status != HammingStatus.CORRECTED:
                ok = False
                print(f"    FAIL value={value} bit={bit}")
                break
        if not ok:
            break
    print(f"    all 256 values x 16 single-bit flips corrected : {ok}")
    assert ok

    print("\n" + "=" * 70)
    print(" ALL HAMMING SELF-TESTS PASSED ")
    print("=" * 70)
