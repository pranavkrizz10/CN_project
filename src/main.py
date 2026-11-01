"""
================================================================================
 main.py  --  COMPLETE DATA LINK LAYER DEMONSTRATION
================================================================================

This is the single entry point that ties the whole project together and shows
every required feature, in order, with detailed output:

   SECTION 1  ERROR CONTROL        -> Hamming codes (correct 1 bit, detect 2)
   SECTION 2  FLOW CONTROL +       -> Go-Back-N ARQ: sliding window, cumulative
              ERROR RECOVERY +        ACKs, timeouts, go-back-N retransmission,
              IN-ORDER DELIVERY       and in-order delivery to the upper layer
   SECTION 3  MULTIPLE ACCESS      -> CSMA/CA: carrier sense, random + binary
                                      exponential backoff, collision avoidance,
                                      RTS/CTS/DATA/ACK handshake
   SECTION 4  PACKET INSPECTION    -> every frame that crossed a wire is saved
                                      to a real .pcap and re-read with PyShark,
                                      which prints the detailed packet content
                                      for each feature.

Run it with:   python3 main.py
================================================================================
"""

import os

import hamming
from hamming import HammingStatus
from channel import Medium, ErrorEvent
from go_back_n import GoBackNSimulation
from csma_ca import Station, CSMACASimulation
from packet_capture import capture_to_pcap, display_pcap_with_pyshark


# Where the generated capture file is written.
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "output")
PCAP_PATH = os.path.join(OUTPUT_DIR, "datalink_capture.pcap")


def banner(text: str):
    """Print a big section banner."""
    print("\n")
    print("#" * 78)
    print("#" + text.center(76) + "#")
    print("#" * 78)


# ------------------------------------------------------------------------------
# SECTION 1 -- ERROR CONTROL with Hamming codes.
# ------------------------------------------------------------------------------
def section_error_control():
    banner(" SECTION 1 : ERROR CONTROL  (Hamming SECDED codes) ")
    print(
        "Hamming codes add parity bits so the receiver can CORRECT a single-bit\n"
        "error and DETECT a double-bit error entirely on its own. Below we encode\n"
        "one byte, then show all three outcomes on its coded form.\n")

    sample = ord('A')                           # the letter 'A' = 0x41
    coded = hamming.encode_byte(sample)
    print(f"  Original data byte : 'A' = 0x{sample:02x} = {sample:08b}")
    print(f"  Hamming-coded form : {coded.hex()}  ({len(coded)} bytes = two 8-bit "
          f"SECDED codewords)\n")

    # (a) clean
    value, status = hamming.decode_byte(coded)
    print(f"  (a) No error      -> decoded 0x{value:02x} '{chr(value)}'  "
          f"status={status.value}")

    # (b) single-bit error -> corrected
    tampered = bytearray(coded)
    tampered[0] ^= 0b00010000                   # flip one bit in the first codeword
    value, status = hamming.decode_byte(bytes(tampered))
    print(f"  (b) 1 bit flipped -> decoded 0x{value:02x} '{chr(value)}'  "
          f"status={status.value}   <- repaired automatically, no retransmit")

    # (c) double-bit error -> detected
    tampered2 = bytearray(coded)
    tampered2[0] ^= 0b00010000
    tampered2[0] ^= 0b00000010                  # a second flip in the SAME codeword
    value, status = hamming.decode_byte(bytes(tampered2))
    print(f"  (c) 2 bits flipped-> status={status.value}   "
          f"<- detected, so Go-Back-N will retransmit this frame")


# ------------------------------------------------------------------------------
# SECTION 2 -- FLOW CONTROL + ERROR RECOVERY + IN-ORDER DELIVERY (Go-Back-N).
# ------------------------------------------------------------------------------
def section_go_back_n():
    banner(" SECTION 2 : FLOW CONTROL + ERROR RECOVERY  (Go-Back-N ARQ) ")

    # A scripted error plan guarantees every behaviour shows up, each in its own
    # round (window size 2 keeps the error events from overlapping):
    #   seq 1 -> single-bit error  (Hamming CORRECTS it in order -> no retransmit)
    #   seq 2 -> frame LOST         (out-of-order discard -> timeout -> go back N)
    #   seq 4 -> double-bit error   (Hamming DETECTS it in order -> retransmit)
    plan = {
        1: ErrorEvent("single", coded_byte_index=0),
        2: ErrorEvent("loss"),
        4: ErrorEvent("double", coded_byte_index=1),
    }
    medium = Medium(name="go-back-n-wire", error_plan=plan)
    sim = GoBackNSimulation(message="DATA-LINK-OK",
                            window_size=2,
                            chunk_size=2,
                            medium=medium)
    events = sim.run()
    return events


# ------------------------------------------------------------------------------
# SECTION 3 -- MULTIPLE ACCESS (CSMA/CA).
# ------------------------------------------------------------------------------
def section_csma_ca():
    banner(" SECTION 3 : MULTIPLE ACCESS  (CSMA/CA) ")

    # Scripted backoffs so the episode deterministically shows a collision, the
    # binary exponential backoff, the freeze/resume behaviour and three clean
    # transmissions.  (See csma_ca.py for the full trace explanation.)
    A = Station("A", "02:00:00:00:00:01", scripted_backoffs=[1, 5])
    B = Station("B", "02:00:00:00:00:02", scripted_backoffs=[3])
    C = Station("C", "02:00:00:00:00:03", scripted_backoffs=[1, 4])
    sim = CSMACASimulation([A, B, C], ap_mac="02:00:00:00:00:AA", use_rts_cts=True)
    events = sim.run()
    return events


# ------------------------------------------------------------------------------
# SECTION 4 -- PACKET CAPTURE + PYSHARK INSPECTION.
# ------------------------------------------------------------------------------
def section_pyshark(gbn_events, csma_events):
    banner(" SECTION 4 : PACKET INSPECTION WITH PYSHARK ")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Every frame that crossed a wire in sections 2 and 3, in time order.
    all_events = gbn_events + csma_events
    print("Saving every transmitted frame as a real Ethernet packet "
          "into a .pcap file...\n")
    capture_to_pcap(all_events, PCAP_PATH)

    # Now read it back with PyShark, one feature at a time, so each block of the
    # report lines up with one assignment feature.
    display_pcap_with_pyshark(
        PCAP_PATH, all_events, feature_filter="go-back-n",
        title="FLOW CONTROL / ERROR CONTROL (Go-Back-N frames)")

    display_pcap_with_pyshark(
        PCAP_PATH, all_events, feature_filter="csma-ca",
        title="MULTIPLE ACCESS (CSMA/CA frames)")

    print(f"\n  The capture file is at: {PCAP_PATH}")
    print("  You can also open it in Wireshark (filter: eth.type == 0x88b5).")


# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------
def main():
    print("=" * 78)
    print(" COMPLETE DATA LINK LAYER".center(78))
    print(" Go-Back-N  +  Hamming Codes  +  CSMA/CA  +  PyShark".center(78))
    print("=" * 78)

    section_error_control()
    gbn_events = section_go_back_n()
    csma_events = section_csma_ca()
    section_pyshark(gbn_events, csma_events)

    banner(" ALL FEATURES DEMONSTRATED SUCCESSFULLY ")
    print(" [x] Error control    : Hamming codes (correct 1-bit, detect 2-bit)")
    print(" [x] Flow control     : Go-Back-N sliding window + cumulative ACKs")
    print(" [x] Error recovery   : timeouts + go-back-N retransmission")
    print(" [x] In-order delivery: receiver delivers frames strictly in sequence")
    print(" [x] Multiple access  : CSMA/CA carrier sense + backoff + RTS/CTS")
    print(" [x] Packet inspection: PyShark detailed dissection of a real .pcap")
    print()


if __name__ == "__main__":
    main()
