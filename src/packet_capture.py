"""
================================================================================
 packet_capture.py  --  REAL packets + PyShark inspection
================================================================================

The assignment asks us to "use PyShark to display the detailed packet content"
for each feature.  PyShark is a Python wrapper around Wireshark's command-line
engine, tshark; it reads a capture file (.pcap) and hands back fully dissected
packets.

So this module does two things:

  1. CAPTURE (write side, using Scapy)
     Every frame that travelled across a wire in our Go-Back-N and CSMA/CA
     simulations is turned into a GENUINE Ethernet packet and saved into a real
     .pcap file.  Because the data link layer in the real world IS Ethernet, we
     wrap each of our data link frames in an Ethernet II header with a custom
     EtherType (0x88B5, reserved for local/experimental use).  The result is a
     normal capture file you could also open in Wireshark itself.

  2. DISPLAY (read side, using PyShark)
     We re-open that .pcap with PyShark and walk through the packets, printing
     the detailed content of each one:
        - the Ethernet header that PyShark dissected (src MAC, dst MAC, type),
        - the raw bytes PyShark read back,
        - our own data link header decoded out of those bytes
          (frame type, sequence number, ACK number, flags, payload),
        - and, for DATA frames, what the Hamming decoder makes of the payload.
     The packets are grouped by the feature they illustrate (error control,
     flow control, multiple access) so the mapping to the assignment is obvious.
================================================================================
"""

from typing import List

from scapy.all import Ether, Raw, wrpcap
import pyshark

import hamming
from hamming import HammingStatus
from frame import Frame, FrameType, FLAG_CORRUPTED
from go_back_n import WireEvent


# A fixed base timestamp so the capture has sensible, increasing packet times.
_BASE_EPOCH = 1_700_000_000.0        # some arbitrary point in time (seconds)


# ------------------------------------------------------------------------------
# CAPTURE: turn our simulated wire events into a real .pcap file with Scapy.
# ------------------------------------------------------------------------------
def capture_to_pcap(wire_events: List[WireEvent], pcap_path: str) -> None:
    """
    Build one Ethernet packet per WireEvent and save them all to `pcap_path`.

    The on-wire bytes are exactly:  Ethernet header  +  our DLL frame bytes.
    """
    packets = []
    for i, ev in enumerate(wire_events):
        dll_bytes = ev.frame.to_bytes()          # our serialized data link frame

        # Wrap the DLL frame in a real Ethernet II header.  Scapy builds the
        # 14-byte header (6 dst + 6 src + 2 type) and appends our bytes as Raw.
        pkt = (Ether(src=ev.frame.src_mac or "02:00:00:00:00:00",
                     dst=ev.frame.dst_mac or "ff:ff:ff:ff:ff:ff",
                     type=Frame.ETHERTYPE)
               / Raw(load=dll_bytes))

        # Give each packet a distinct, increasing capture timestamp.
        pkt.time = _BASE_EPOCH + i * 0.001
        packets.append(pkt)

    wrpcap(pcap_path, packets)
    print(f"  Wrote {len(packets)} Ethernet packets to '{pcap_path}'")


# ------------------------------------------------------------------------------
# Helper: decode our DLL header out of the raw payload bytes PyShark read.
# ------------------------------------------------------------------------------
def _describe_dll(payload: bytes) -> str:
    """Return a detailed, multi-line description of one data link frame."""
    ftype = FrameType(payload[0])
    seq = payload[1]
    ack = payload[2]
    flags = payload[3]
    plen = (payload[4] << 8) | payload[5]
    body = payload[6:6 + plen]

    lines = []
    lines.append(f"      Data-Link header:")
    lines.append(f"          frame_type = {ftype.name} ({int(ftype)})")
    lines.append(f"          seq_num    = {seq}")
    lines.append(f"          ack_num    = {ack}")
    corrupt = " (CORRUPTED flag set by medium)" if (flags & FLAG_CORRUPTED) else ""
    lines.append(f"          flags      = 0x{flags:02x}{corrupt}")
    lines.append(f"          payload_len= {plen} byte(s)")

    if ftype == FrameType.DATA and plen > 0:
        lines.append(f"          payload    = {body.hex()}  (Hamming-coded)")
        # Run the Hamming decoder on exactly the bytes PyShark gave us.
        data, status, corrected = hamming.decode_bytes(body)
        if status == HammingStatus.DOUBLE_ERROR:
            verdict = "DOUBLE-bit error DETECTED (uncorrectable -> frame dropped)"
        elif status == HammingStatus.CORRECTED:
            verdict = f"single-bit error CORRECTED ({corrected} byte(s) repaired)"
        else:
            verdict = "no error"
        lines.append(f"          Hamming    = {verdict}")
        if status == HammingStatus.DOUBLE_ERROR:
            # The decoder cannot trust ANY of the bits in a double-error frame,
            # so showing its "decoded" text would be misleading garbage.  The
            # receiver discards this frame and Go-Back-N retransmits it.
            lines.append(f"          decoded    = (none - frame discarded, "
                         f"data cannot be trusted)")
        else:
            shown = data.decode("utf-8", errors="replace")
            lines.append(f"          decoded    = '{shown}'")
    return "\n".join(lines)


# ------------------------------------------------------------------------------
# DISPLAY: re-read the .pcap with PyShark and print detailed packet content.
# ------------------------------------------------------------------------------
def display_pcap_with_pyshark(pcap_path: str,
                              wire_events: List[WireEvent],
                              feature_filter: str = None,
                              title: str = "") -> None:
    """
    Open `pcap_path` with PyShark and print each packet's dissected content.

    If `feature_filter` is given (e.g. "go-back-n" or "csma-ca"), only packets
    belonging to that feature are shown, so each section of the report maps
    cleanly onto one assignment feature.
    """
    bar = "=" * 78
    print("\n" + bar)
    print(f" PYSHARK PACKET INSPECTION {('-- ' + title) if title else ''}")
    print(bar)
    print(" (each packet below was written by Scapy and read back by PyShark)\n")

    # use_json + include_raw lets us pull the exact raw bytes back out.
    cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True)

    shown = 0
    try:
        for idx, pkt in enumerate(cap):
            ev = wire_events[idx]                    # same order as written
            if feature_filter and ev.feature != feature_filter:
                continue
            shown += 1

            # --- The Ethernet layer, dissected natively by PyShark/tshark. ---
            eth = pkt.eth
            raw = pkt.get_raw_packet()               # full frame bytes
            dll_payload = raw[14:]                    # strip 14-byte Ethernet hdr

            print(f"  ---- Packet #{pkt.number}  "
                  f"[{ev.feature}]  ({ev.direction})  note: {ev.note} ----")
            print(f"      Ethernet II (dissected by PyShark):")
            print(f"          src MAC    = {eth.src}")
            print(f"          dst MAC    = {eth.dst}")
            print(f"          EtherType  = {eth.type}  (custom data-link protocol)")
            print(f"          frame len  = {pkt.length} bytes on the wire")
            # --- Our data link frame, decoded from the bytes PyShark returned. ---
            print(_describe_dll(dll_payload))
            print()
    finally:
        cap.close()

    print(f"  PyShark displayed {shown} packet(s).")


# ------------------------------------------------------------------------------
# Stand-alone demo: build a tiny pcap and inspect it.
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Make three sample frames by hand just to exercise the module on its own.
    evs = [
        WireEvent(1, "S->R",
                  Frame(FrameType.DATA, seq_num=0, payload=hamming.encode_bytes(b"Hi"),
                        original_text="Hi"),
                  "clean", "go-back-n"),
        WireEvent(2, "R->S",
                  Frame(FrameType.ACK, ack_num=1,
                        src_mac="02:00:00:00:00:02", dst_mac="02:00:00:00:00:01"),
                  "cumulative ACK=1", "go-back-n"),
        WireEvent(3, "MAC",
                  Frame(FrameType.RTS, src_mac="02:00:00:00:00:03",
                        dst_mac="02:00:00:00:00:AA"),
                  "A sends RTS", "csma-ca"),
    ]
    capture_to_pcap(evs, "/tmp/sample.pcap")
    display_pcap_with_pyshark("/tmp/sample.pcap", evs, title="SELF TEST")