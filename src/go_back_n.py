"""
================================================================================
 go_back_n.py  --  FLOW CONTROL + ERROR RECOVERY  (Go-Back-N ARQ)
================================================================================

Go-Back-N is a "sliding window" Automatic Repeat reQuest (ARQ) protocol.  It
gives the data link layer two things at once:

  1. FLOW CONTROL
     The sender may have at most N unacknowledged frames "in flight" at a time.
     N is the window size.  The sender cannot race ahead and flood the receiver;
     it must wait for acknowledgements before the window can slide forward.

  2. RELIABLE, IN-ORDER DELIVERY (error recovery)
     * The receiver only ever accepts frames IN ORDER.  It keeps a single
       variable `expected_seq` = the sequence number it wants next.
     * Any frame that is out of order, or that arrives damaged, is DISCARDED.
     * The receiver sends CUMULATIVE acknowledgements: an ACK with ack_num = K
       means "I have correctly received everything up to and including K-1, now
       send me K."
     * If the sender's timer for the oldest unacknowledged frame expires (an ACK
       never came back, because a frame or its ACK was lost or damaged), the
       sender "goes back N": it retransmits that frame AND every frame sent after
       it.  That is where the name comes from.

HOW ERROR CONTROL (Hamming) PLUGS IN HERE
-----------------------------------------
Every DATA frame's payload is Hamming-coded (see hamming.py).  When a frame
arrives, the receiver decodes it:

    * NO_ERROR   -> perfect, accept it.
    * CORRECTED  -> a single bit was flipped in transit but Hamming repaired it
                    completely.  The frame is ACCEPTED and delivered -- NO
                    retransmission is needed.  (This is the whole point of using
                    an error-CORRECTING code at the link layer.)
    * DOUBLE_ERROR -> two bits were flipped; Hamming can detect but not fix this.
                    The frame is DISCARDED, forcing Go-Back-N to retransmit it.

SEQUENCE NUMBERS
----------------
Our frame header stores the sequence number in one byte, so the sequence space
is 0..255 (modulus 256).  The textbook requirement for Go-Back-N is simply
N <= modulus - 1; with a small window like N=4 we are comfortably within that,
so sequence numbers are unambiguous and easy to read in the output.

This simulation is DETERMINISTIC and event-stepped (no real threads/sockets) so
that every run reliably demonstrates every feature in a readable order.
================================================================================
"""

from dataclasses import dataclass
from typing import List, Optional

import hamming
from hamming import HammingStatus
from frame import Frame, FrameType
from channel import Medium


# ------------------------------------------------------------------------------
# A record of one frame that actually travelled across a wire.  We collect these
# so packet_capture.py can turn the whole conversation into a real .pcap file.
# ------------------------------------------------------------------------------
@dataclass
class WireEvent:
    tick: int           # logical time the event happened
    direction: str      # "S->R" (data path) or "R->S" (ack path)
    frame: Frame        # the frame as it LEFT the sender/receiver
    note: str           # short human description ("clean", "LOST", "corrected"...)
    feature: str        # which concept this illustrates (for PyShark grouping)


# A tidy coloured-free banner helper so the console output has clear sections.
def _line(char="-", width=78):
    return char * width


class GoBackNSimulation:
    """
    Drives a full Go-Back-N exchange of a text message, chopping it into frames,
    pushing them through a lossy/noisy Medium, and handling ACKs, timeouts and
    retransmissions.
    """

    def __init__(self,
                 message: str,
                 window_size: int = 4,
                 chunk_size: int = 2,
                 medium: Optional[Medium] = None,
                 src_mac: str = "02:00:00:00:00:01",
                 dst_mac: str = "02:00:00:00:00:02"):
        self.message = message
        self.window_size = window_size            # N: max frames in flight
        self.chunk_size = chunk_size              # payload bytes per DATA frame
        self.medium = medium if medium is not None else Medium()
        self.src_mac = src_mac
        self.dst_mac = dst_mac

        # Split the message into fixed-size chunks; each chunk becomes one frame.
        self.chunks: List[bytes] = [
            message[i:i + chunk_size].encode("utf-8")
            for i in range(0, len(message), chunk_size)
        ]
        self.total_frames = len(self.chunks)

        # ---- Sender state ----
        self.base = 0            # seq of the oldest UNACKNOWLEDGED frame
        self.next_seq = 0        # seq of the next NEW frame to send
        # ---- Receiver state ----
        self.expected_seq = 0    # the seq number the receiver wants next
        self.delivered: List[bytes] = []   # bytes handed up to the layer above

        # Logical clock + bookkeeping.
        self.tick = 0
        self.wire_events: List[WireEvent] = []
        self.timeouts = 0
        self.retransmissions = 0
        self.corrected_frames = 0

    # --------------------------------------------------------------------------
    # Small helper: build one DATA frame for a given sequence number, with its
    # payload Hamming-coded.
    # --------------------------------------------------------------------------
    def _make_data_frame(self, seq: int) -> Frame:
        original = self.chunks[seq]
        coded = hamming.encode_bytes(original)        # <-- ERROR CONTROL applied
        return Frame(FrameType.DATA, seq_num=seq, payload=coded,
                     src_mac=self.src_mac, dst_mac=self.dst_mac,
                     original_text=original.decode("utf-8", errors="replace"))

    # --------------------------------------------------------------------------
    # The receiver's reaction to ONE arriving DATA frame.
    # Returns the ACK frame the receiver sends back (always, cumulative).
    # --------------------------------------------------------------------------
    def _receiver_process(self, arrived: Frame) -> Frame:
        # 1) Run the Hamming decoder to find out what shape the payload is in.
        data, status, corrected = hamming.decode_bytes(arrived.payload)

        if status == HammingStatus.DOUBLE_ERROR:
            # Damaged beyond repair -> discard, do not advance, re-ACK old value.
            print(f"      RECV  seq={arrived.seq_num}: payload has a DOUBLE-bit "
                  f"error -> DISCARDED (Hamming can't fix). "
                  f"Re-ACK expecting {self.expected_seq}")
        elif arrived.seq_num != self.expected_seq:
            # Correct bits, but wrong order (an earlier frame is missing).
            # Go-Back-N receivers refuse to buffer these; they drop them.
            fixed = " (single-bit error was CORRECTED by Hamming)" if status == HammingStatus.CORRECTED else ""
            print(f"      RECV  seq={arrived.seq_num}: OUT OF ORDER "
                  f"(expected {self.expected_seq}){fixed} -> DISCARDED. "
                  f"Re-ACK expecting {self.expected_seq}")
        else:
            # Correct bits AND in order -> accept and deliver it upward.
            if status == HammingStatus.CORRECTED:
                self.corrected_frames += 1
                print(f"      RECV  seq={arrived.seq_num}: single-bit error "
                      f"CORRECTED by Hamming, data='{data.decode('utf-8', errors='replace')}' "
                      f"-> ACCEPTED (no retransmit needed)")
            else:
                print(f"      RECV  seq={arrived.seq_num}: clean, "
                      f"data='{data.decode('utf-8', errors='replace')}' -> ACCEPTED")
            self.delivered.append(data)
            self.expected_seq += 1          # slide what we expect next

        # The receiver ALWAYS replies with a cumulative ACK telling the sender
        # the next sequence number it wants.
        return Frame(FrameType.ACK, ack_num=self.expected_seq,
                     src_mac=self.dst_mac, dst_mac=self.src_mac)

    # --------------------------------------------------------------------------
    # Record a frame that crossed a wire (for the pcap) and bump the clock.
    # --------------------------------------------------------------------------
    def _record(self, direction: str, frame: Frame, note: str, feature: str):
        self.tick += 1
        self.wire_events.append(WireEvent(self.tick, direction, frame, note, feature))

    # --------------------------------------------------------------------------
    # RUN the whole exchange.
    # --------------------------------------------------------------------------
    def run(self) -> List[WireEvent]:
        print(_line("="))
        print(" GO-BACK-N ARQ  --  flow control, error recovery & in-order delivery")
        print(_line("="))
        print(f" Message to send : {self.message!r}")
        print(f" Window size N   : {self.window_size}")
        print(f" Payload / frame : {self.chunk_size} byte(s)")
        print(f" Total frames    : {self.total_frames}")
        print(_line())

        round_no = 0
        safety = 0            # guard against any accidental infinite loop
        while self.base < self.total_frames and safety < 1000:
            safety += 1
            round_no += 1
            print(f"\n[ROUND {round_no}]  window = [base={self.base} .. "
                  f"{self.base + self.window_size - 1}]   next_to_send={self.next_seq}")

            progress_before = self.base

            # ---------------------------------------------------------------
            # SEND PHASE: transmit every NEW frame allowed by the window.
            # Flow control lives in this one condition:
            #     next_seq < base + N   AND   next_seq < total_frames
            # ---------------------------------------------------------------
            sent_this_round: List[int] = []
            while (self.next_seq < self.base + self.window_size
                   and self.next_seq < self.total_frames):
                frame = self._make_data_frame(self.next_seq)
                print(f"  SEND  {frame.summary()}   "
                      f"[window slot {self.next_seq - self.base + 1}/{self.window_size}]")
                sent_this_round.append(self.next_seq)
                self.next_seq += 1

            # If the window is full and there is still data waiting, say so:
            if (self.next_seq >= self.base + self.window_size
                    and self.next_seq < self.total_frames):
                print(f"  FLOW CONTROL: window FULL ({self.window_size} frames in "
                      f"flight). Must wait for ACKs before sending seq={self.next_seq}.")

            # ---------------------------------------------------------------
            # DELIVERY PHASE: each sent frame crosses the medium (which may
            # damage or lose it), the receiver reacts, and an ACK comes back.
            # ---------------------------------------------------------------
            highest_ack = self.base
            for seq in sent_this_round:
                frame = self._make_data_frame(seq)

                # --- forward trip: sender -> receiver, through the medium ---
                arrived, note = self.medium.transmit(frame)
                # Capture the frame AS IT TRAVELLED on the wire: if the medium
                # corrupted it, we record the corrupted bytes (so PyShark later
                # shows the real damaged payload and the Hamming verdict on it);
                # if it was lost, the sender still transmitted the clean frame,
                # so we record that.
                on_wire = arrived if arrived is not None else frame
                self._record("S->R", on_wire, note, feature="go-back-n")

                if arrived is None:
                    # The medium LOST this frame; the receiver never sees it and
                    # therefore sends no ACK.  Its timer at the sender will fire.
                    print(f"      WIRE  seq={seq}: {note}  (no ACK will return)")
                    continue

                if note != "clean":
                    print(f"      WIRE  seq={seq}: {note}")

                # --- receiver handles it and produces a cumulative ACK ---
                ack = self._receiver_process(arrived)

                # --- return trip: receiver -> sender (ACKs assumed clean) ---
                self._record("R->S", ack, f"cumulative ACK={ack.ack_num}",
                             feature="go-back-n")
                print(f"      ACK   receiver -> sender: ack={ack.ack_num} "
                      f"(\"send me {ack.ack_num} next\")")

                # --- sender processes the ACK: slide the window forward ---
                if ack.ack_num > highest_ack:
                    highest_ack = ack.ack_num

            # Sliding the window: base moves up to the highest cumulative ACK.
            if highest_ack > self.base:
                print(f"  SLIDE window: base {self.base} -> {highest_ack} "
                      f"(frames {self.base}..{highest_ack - 1} acknowledged)")
                self.base = highest_ack

            # ---------------------------------------------------------------
            # TIMEOUT PHASE: if the oldest unacknowledged frame still has not
            # been acknowledged, its timer expires -> GO BACK N.
            # ---------------------------------------------------------------
            if self.base == progress_before and self.base < self.total_frames:
                self.timeouts += 1
                # Count how many frames must be resent (the whole outstanding window).
                to_resend = self.next_seq - self.base
                self.retransmissions += to_resend
                print(f"  !! TIMEOUT: no progress for base={self.base}. "
                      f"GO BACK N -> rewind next_to_send from {self.next_seq} "
                      f"to {self.base} and retransmit {to_resend} frame(s).")
                self.next_seq = self.base      # <-- the "go back N" rewind

        # ---------------------------------------------------------------
        # DONE.  Verify the receiver reconstructed the original message.
        # ---------------------------------------------------------------
        reassembled = b"".join(self.delivered).decode("utf-8", errors="replace")
        print("\n" + _line("="))
        print(" GO-BACK-N COMPLETE")
        print(_line("="))
        print(f"  Frames delivered IN ORDER : {len(self.delivered)}/{self.total_frames}")
        print(f"  Single-bit errors fixed   : {self.corrected_frames} "
              f"(by Hamming, no retransmit)")
        print(f"  Timeouts (go-back-N)      : {self.timeouts}")
        print(f"  Frames retransmitted      : {self.retransmissions}")
        print(f"  Reassembled message       : {reassembled!r}")
        ok = (reassembled == self.message)
        print(f"  Message intact?           : {'YES ✓' if ok else 'NO ✗'}")
        assert ok, "Go-Back-N failed to deliver the message intact!"
        return self.wire_events


# ------------------------------------------------------------------------------
# Stand-alone demo so you can run just this protocol: `python3 go_back_n.py`
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    from channel import ErrorEvent

    # A scripted error plan that forces every feature to appear in its own,
    # cleanly separated round (window size 2 keeps the errors from overlapping):
    #   seq 1 -> a single-bit error (Hamming CORRECTS it in-order, no retransmit)
    #   seq 2 -> the frame is LOST   (out-of-order discard -> timeout -> go back N)
    #   seq 4 -> a double-bit error  (Hamming DETECTS it in-order -> retransmit)
    plan = {
        1: ErrorEvent("single", coded_byte_index=0),
        2: ErrorEvent("loss"),
        4: ErrorEvent("double", coded_byte_index=1),
    }
    sim = GoBackNSimulation("DATA-LINK-OK", window_size=2, chunk_size=2,
                            medium=Medium(name="demo-wire", error_plan=plan))
    sim.run()
