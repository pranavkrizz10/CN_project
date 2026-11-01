"""
================================================================================
 channel.py  --  The physical MEDIUM between sender and receiver
================================================================================

The data link layer sits on top of an imperfect physical medium.  This module
simulates that medium for the point-to-point Go-Back-N link.  Its whole job is
to be *unreliable* in controlled, repeatable ways so we can watch the upper
layers cope:

    * It can FLIP BITS in a frame's payload.
        - 1 flipped bit per coded byte  -> Hamming CORRECTS it (no retransmit).
        - 2 flipped bits in one coded byte -> Hamming only DETECTS it; the frame
          is treated as damaged and Go-Back-N must retransmit.
    * It can LOSE a frame entirely.
        - The sender never gets an ACK, its timer expires, and Go-Back-N
          retransmits the whole window.

To keep the demonstration deterministic (so every run clearly shows every
feature, instead of relying on luck), the medium follows a scripted "error
plan": a dictionary that says, for a given sequence number on its FIRST
transmission, what should go wrong.  Retransmissions are delivered cleanly, so
the protocol always makes forward progress -- exactly like a real recovering
link.
================================================================================
"""

import random
from dataclasses import dataclass, field
from typing import Dict, Optional

from frame import Frame, FLAG_CORRUPTED


# ------------------------------------------------------------------------------
# Low-level bit-twiddling helper shared by this module and CSMA/CA.
# ------------------------------------------------------------------------------
def flip_bit(data: bytearray, byte_index: int, bit_index: int) -> None:
    """Flip bit `bit_index` (0 = most-significant) of byte `byte_index` in place."""
    data[byte_index] ^= (1 << (7 - bit_index))


# ------------------------------------------------------------------------------
# The kinds of damage the medium can apply to a frame on its first trip.
# ------------------------------------------------------------------------------
@dataclass
class ErrorEvent:
    kind: str                 # "single", "double", or "loss"
    coded_byte_index: int = 0 # which byte of the coded payload to hit


@dataclass
class Medium:
    """
    A one-way, lossy, noisy link from a sender to a receiver.

    error_plan : maps a DATA frame's seq_num -> ErrorEvent to apply the FIRST
                 time that seq_num is transmitted.  After that the frame travels
                 clean, so retransmissions succeed.
    """
    name: str = "wire"
    error_plan: Dict[int, ErrorEvent] = field(default_factory=dict)
    random_ber: float = 0.0          # optional random bit-error rate (unused in scripted demo)
    seed: Optional[int] = None
    _already_hit: set = field(default_factory=set)   # seqs we've already damaged

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    # --------------------------------------------------------------------------
    # transmit(): push a frame across the medium.
    #
    # Returns a tuple (delivered_frame_or_None, event_description):
    #   - delivered_frame_or_None is None if the frame was LOST,
    #     otherwise it's the (possibly corrupted) Frame that arrived.
    #   - event_description is a short human string for the log/output.
    # --------------------------------------------------------------------------
    def transmit(self, frame: Frame):
        # ACKs/NAKs/control frames in this simple model travel cleanly; we only
        # script damage against DATA frames, which keeps the demo easy to follow.
        raw = bytearray(frame.to_bytes())

        # Is there a scripted error for this seq that we have NOT yet applied?
        event: Optional[ErrorEvent] = None
        if frame.seq_num in self.error_plan and frame.seq_num not in self._already_hit:
            event = self.error_plan[frame.seq_num]
            self._already_hit.add(frame.seq_num)

        # ---- Case A: no scripted error -> maybe apply random noise, else clean.
        if event is None:
            if self.random_ber > 0.0:
                for byte_i in range(6, len(raw)):          # skip the 6-byte header
                    for bit_i in range(8):
                        if self._rng.random() < self.random_ber:
                            flip_bit(raw, byte_i, bit_i)
            arrived = Frame.from_bytes(bytes(raw), frame.src_mac, frame.dst_mac)
            arrived.original_text = frame.original_text
            return arrived, "clean"

        # ---- Case B: scripted LOSS -> the frame simply vanishes.
        if event.kind == "loss":
            return None, "LOST (frame dropped by medium)"

        # ---- Case C: scripted bit flips in the coded payload.
        # The coded payload starts at byte index 6 (after the fixed header).
        payload_start = 6
        target = payload_start + event.coded_byte_index
        if target >= len(raw):
            target = len(raw) - 1               # safety clamp

        if event.kind == "single":
            flip_bit(raw, target, 3)            # one bit -> Hamming will fix it
            desc = f"1-bit error injected in coded byte #{event.coded_byte_index}"
        elif event.kind == "double":
            flip_bit(raw, target, 2)            # two bits in the SAME coded byte
            flip_bit(raw, target, 5)            # -> Hamming detects but can't fix
            desc = f"2-bit error injected in coded byte #{event.coded_byte_index}"
        else:
            desc = "unknown error kind"

        arrived = Frame.from_bytes(bytes(raw), frame.src_mac, frame.dst_mac)
        arrived.flags |= FLAG_CORRUPTED         # mark it so the log is honest
        arrived.original_text = frame.original_text
        return arrived, desc
