"""
================================================================================
 frame.py  --  The DATA LINK LAYER FRAME format
================================================================================

The data link layer does not send a naked stream of bytes; it groups bytes into
*frames*.  A frame is a small structured unit with a header (control info) and a
payload (the actual data).  This file defines our frame format and the code to
turn a frame into bytes (serialize) and back (parse).

Because the data link layer in the real world is Ethernet, we deliberately give
every frame a source and destination MAC address.  Later (in packet_capture.py)
each of these frames is written out as a genuine Ethernet packet so that PyShark
/ Wireshark can dissect it.

ON-THE-WIRE LAYOUT
------------------
The MAC addresses travel in the Ethernet header.  Everything below is the
*payload* that sits inside the Ethernet frame (after our custom EtherType):

    byte 0      : frame_type   (1 = DATA, 2 = ACK, 3 = NAK, 4 = RTS, 5 = CTS)
    byte 1      : seq_num      (sequence number of this frame, 0-255)
    byte 2      : ack_num      (the next sequence number the receiver expects)
    byte 3      : flags        (bit0 = payload was corrupted in transit, info only)
    bytes 4-5   : payload_len  (length of the coded payload, big-endian uint16)
    bytes 6..   : payload      (Hamming-CODED data bytes)

Keeping the header fixed-size and simple makes the hex dump easy to read in the
PyShark output.
================================================================================
"""

from enum import IntEnum
from typing import Optional


# ------------------------------------------------------------------------------
# The kinds of frame our protocols exchange.  IntEnum so the value is the byte
# that actually goes on the wire.
# ------------------------------------------------------------------------------
class FrameType(IntEnum):
    DATA = 1     # carries user data (Go-Back-N)
    ACK  = 2     # positive acknowledgement (Go-Back-N, CSMA/CA)
    NAK  = 3     # negative acknowledgement (frame arrived damaged)
    RTS  = 4     # Request To Send  (CSMA/CA handshake)
    CTS  = 5     # Clear To Send    (CSMA/CA handshake)


# A couple of handy constants for the flags byte.
FLAG_NONE      = 0x00
FLAG_CORRUPTED = 0x01     # set by the medium if it damaged the payload in transit


class Frame:
    """
    One data link layer frame.

    We hold on to BOTH the Hamming-coded payload (what travels on the wire) and,
    when we know it, the original text, purely so the demo output is readable.
    """

    # Magic EtherType we use so Wireshark groups our frames together.  0x88B5 is
    # officially reserved for "local experimental" use, which is exactly us.
    ETHERTYPE = 0x88B5

    def __init__(self,
                 frame_type: FrameType,
                 seq_num: int = 0,
                 ack_num: int = 0,
                 payload: bytes = b"",
                 flags: int = FLAG_NONE,
                 src_mac: str = "02:00:00:00:00:01",
                 dst_mac: str = "02:00:00:00:00:02",
                 original_text: Optional[str] = None):
        self.frame_type = FrameType(frame_type)
        self.seq_num = seq_num & 0xFF          # keep inside one byte
        self.ack_num = ack_num & 0xFF
        self.payload = payload                 # Hamming-CODED bytes
        self.flags = flags
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.original_text = original_text      # pre-Hamming text, for display only

    # --------------------------------------------------------------------------
    # SERIALIZE: Frame object -> bytes (the Ethernet payload).
    # --------------------------------------------------------------------------
    def to_bytes(self) -> bytes:
        header = bytes([
            int(self.frame_type) & 0xFF,
            self.seq_num & 0xFF,
            self.ack_num & 0xFF,
            self.flags & 0xFF,
            (len(self.payload) >> 8) & 0xFF,   # payload length high byte
            len(self.payload) & 0xFF,          # payload length low byte
        ])
        return header + self.payload

    # --------------------------------------------------------------------------
    # PARSE: bytes -> Frame object.  (Static so you call Frame.from_bytes(...).)
    # --------------------------------------------------------------------------
    @staticmethod
    def from_bytes(raw: bytes,
                   src_mac: str = "",
                   dst_mac: str = "") -> "Frame":
        frame_type = FrameType(raw[0])
        seq_num = raw[1]
        ack_num = raw[2]
        flags = raw[3]
        payload_len = (raw[4] << 8) | raw[5]
        payload = raw[6:6 + payload_len]
        return Frame(frame_type, seq_num, ack_num, payload, flags,
                     src_mac or "", dst_mac or "")

    # --------------------------------------------------------------------------
    # A compact, human-friendly one-line description used all over the output.
    # --------------------------------------------------------------------------
    def summary(self) -> str:
        if self.frame_type == FrameType.DATA:
            extra = f"seq={self.seq_num}"
            if self.original_text is not None:
                extra += f" data='{self.original_text}'"
        elif self.frame_type in (FrameType.ACK, FrameType.NAK):
            extra = f"ack={self.ack_num}"
        else:  # RTS / CTS
            extra = f"{self.src_mac} -> {self.dst_mac}"
        return f"{self.frame_type.name:4s} {extra}"

    def __repr__(self) -> str:
        return (f"Frame(type={self.frame_type.name}, seq={self.seq_num}, "
                f"ack={self.ack_num}, payload_len={len(self.payload)})")
