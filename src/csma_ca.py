"""
================================================================================
 csma_ca.py  --  MULTIPLE ACCESS  (CSMA/CA, the Wi-Fi / IEEE 802.11 method)
================================================================================

When many stations share ONE medium (one radio channel, one cable), they need a
rule for deciding who gets to transmit and when, so their signals do not collide
and destroy each other.  That rule is a Medium Access Control (MAC) protocol.

CSMA/CA = Carrier Sense Multiple Access with Collision AVOIDANCE.  It is what
Wi-Fi uses, because on radio a station cannot reliably hear a collision while it
transmits (so the "Collision Detection" of wired Ethernet is impossible).
Instead of detecting collisions, CSMA/CA tries hard to AVOID them:

  1. CARRIER SENSE
     Before transmitting, a station listens.  If the medium is busy, it waits.

  2. DIFS + RANDOM BACKOFF
     Even once the medium goes idle, a station does NOT transmit immediately.
     It waits a fixed gap (DIFS) and then counts down a RANDOM backoff timer,
     chosen uniformly from the "contention window" [0, CW-1].  Choosing random
     values makes it unlikely that two stations pick the same instant.

  3. FREEZE AND RESUME
     While counting down, if the medium becomes busy (someone else started), the
     station FREEZES its counter and resumes from the same value afterwards.
     This gives waiting stations a fair head-start next time -- a key fairness
     property of CSMA/CA.

  4. TRANSMIT WHEN COUNTER HITS ZERO
     The station whose timer reaches 0 first wins and transmits.

  5. RTS / CTS HANDSHAKE (virtual carrier sense)
     Optionally the winner first exchanges short RTS (Request To Send) and CTS
     (Clear To Send) frames with the receiver.  Everyone who hears them sets a
     NAV (Network Allocation Vector) = "stay quiet for this long", which avoids
     the hidden-terminal problem.  Then: DATA, and finally an ACK after a short
     gap (SIFS).

  6. COLLISION -> BINARY EXPONENTIAL BACKOFF
     If two stations' timers hit 0 in the same slot they transmit together and
     collide.  No ACK comes back, so each DOUBLES its contention window (CW) and
     tries again with a fresh, larger random backoff.  Doubling spreads retries
     out, so repeated collisions become rapidly less likely.

This module runs a DETERMINISTIC, slot-by-slot simulation of several stations
contending for one access point, so the output clearly shows a collision, the
exponential backoff, the freeze/resume behaviour, and several clean successes.
================================================================================
"""

import random
from typing import Dict, List, Optional

import hamming                            # for Hamming-coding DATA payloads
from frame import Frame, FrameType
from go_back_n import WireEvent          # reuse the pcap-event record type


def _line(char="-", width=78):
    return char * width


# ------------------------------------------------------------------------------
# One contending station.
# ------------------------------------------------------------------------------
class Station:
    CW_MIN = 4          # smallest contention window -> backoff in [0, 3]
    CW_MAX = 64         # ceiling for the contention window

    def __init__(self, name: str, mac: str, scripted_backoffs: Optional[List[int]] = None):
        self.name = name
        self.mac = mac
        self.cw = Station.CW_MIN
        self.backoff = 0
        self.done = False               # True once its frame is delivered
        self.collisions = 0
        self.successes = 0
        # Deterministic backoff values (popped in order).  When this list runs
        # out we fall back to real randomness from the shared RNG.
        self._scripted = list(scripted_backoffs) if scripted_backoffs else []

    def choose_backoff(self, rng: random.Random) -> int:
        """Pick a fresh backoff from [0, CW-1] (scripted first, else random)."""
        if self._scripted:
            self.backoff = self._scripted.pop(0)
        else:
            self.backoff = rng.randint(0, self.cw - 1)
        return self.backoff

    def on_collision(self, rng: random.Random):
        """React to a collision: binary exponential backoff (double the CW)."""
        self.collisions += 1
        self.cw = min(self.cw * 2, Station.CW_MAX)       # <-- double the window
        self.choose_backoff(rng)


# ------------------------------------------------------------------------------
# The CSMA/CA simulation over one shared medium and one access point (AP).
# ------------------------------------------------------------------------------
class CSMACASimulation:

    # Fixed timing gaps, expressed in abstract "slots" to keep the demo readable.
    DIFS = 2            # idle gap a station waits before counting down
    SIFS = 1            # short gap before ACK / CTS
    TX_SLOTS = 3        # slots a successful RTS/CTS/DATA/ACK exchange occupies
    JAM_SLOTS = 2       # slots a collision wastes before everyone realises

    def __init__(self,
                 stations: List[Station],
                 ap_mac: str = "02:00:00:00:00:AA",
                 use_rts_cts: bool = True,
                 seed: int = 7):
        self.stations = stations
        self.ap_mac = ap_mac
        self.use_rts_cts = use_rts_cts
        self.rng = random.Random(seed)
        self.slot = 0
        self.wire_events: List[WireEvent] = []
        self.total_collisions = 0

    def _record(self, frame: Frame, note: str):
        self.slot += 0   # frames share the current slot's timestamp
        self.wire_events.append(
            WireEvent(self.slot, "MAC", frame, note, feature="csma-ca"))

    # --------------------------------------------------------------------------
    # Emit the RTS/CTS/DATA/ACK burst for a station that won the medium.
    # --------------------------------------------------------------------------
    def _successful_exchange(self, st: Station):
        print(f"    slot {self.slot:>3}: *** {st.name} wins the medium "
              f"(backoff reached 0) ***")

        if self.use_rts_cts:
            # RTS: station -> AP.  Announces how long the medium will be busy.
            rts = Frame(FrameType.RTS, src_mac=st.mac, dst_mac=self.ap_mac)
            self._record(rts, f"{st.name} sends RTS (Request To Send)")
            print(f"            RTS  {st.name} -> AP   : 'may I send?'  "
                  f"(all others set NAV and stay quiet)")

            # CTS: AP -> station, after a short SIFS gap.
            cts = Frame(FrameType.CTS, src_mac=self.ap_mac, dst_mac=st.mac)
            self._record(cts, "AP replies CTS (Clear To Send)")
            print(f"            CTS  AP -> {st.name}   : 'go ahead'  (after SIFS)")

        # DATA: station -> AP.  The payload is Hamming-coded, exactly like in
        # Go-Back-N -- error control is a data-link function that applies to
        # every DATA frame, whatever MAC protocol carried it to the medium.
        text = f"from {st.name}"
        payload = hamming.encode_bytes(text.encode("utf-8"))
        data = Frame(FrameType.DATA, seq_num=st.successes, payload=payload,
                     src_mac=st.mac, dst_mac=self.ap_mac,
                     original_text=text)
        self._record(data, f"{st.name} transmits DATA")
        print(f"            DATA {st.name} -> AP   : sending its frame")

        # ACK: AP -> station, after SIFS.  This confirms success.
        ack = Frame(FrameType.ACK, src_mac=self.ap_mac, dst_mac=st.mac)
        self._record(ack, "AP acknowledges the DATA")
        print(f"            ACK  AP -> {st.name}   : received OK  (after SIFS)")

        st.done = True
        st.successes += 1
        st.cw = Station.CW_MIN          # success -> reset contention window
        # The medium is now busy for the whole exchange; everyone else deferred.
        print(f"            medium BUSY for {self.TX_SLOTS} slots; "
              f"other stations FREEZE their backoff counters.")

    # --------------------------------------------------------------------------
    # Handle a collision between two or more stations.
    # --------------------------------------------------------------------------
    def _collision(self, colliders: List[Station]):
        self.total_collisions += 1
        names = ", ".join(s.name for s in colliders)
        print(f"    slot {self.slot:>3}: !!! COLLISION !!! {names} "
              f"transmitted in the SAME slot")
        for st in colliders:
            # Their RTS/DATA frames collided, so record them as collided frames.
            f = Frame(FrameType.RTS if self.use_rts_cts else FrameType.DATA,
                      src_mac=st.mac, dst_mac=self.ap_mac)
            self._record(f, f"{st.name}'s frame destroyed in collision")
        for st in colliders:
            old_cw = st.cw
            st.on_collision(self.rng)
            print(f"            {st.name}: no ACK -> binary exponential backoff, "
                  f"CW {old_cw} -> {st.cw}, new random backoff = {st.backoff}")
        print(f"            medium wasted for {self.JAM_SLOTS} slots.")

    # --------------------------------------------------------------------------
    # RUN the whole contention episode.
    # --------------------------------------------------------------------------
    def run(self) -> List[WireEvent]:
        print(_line("="))
        print(" CSMA/CA  --  multiple access with collision avoidance")
        print(_line("="))
        print(f" Stations contending : {', '.join(s.name for s in self.stations)}")
        print(f" Access point (AP)   : {self.ap_mac}")
        print(f" RTS/CTS handshake   : {'ON' if self.use_rts_cts else 'OFF'}")
        print(f" CWmin / CWmax       : {Station.CW_MIN} / {Station.CW_MAX}")
        print(_line())

        # Everyone picks an initial random backoff after sensing idle + DIFS.
        print(f"\n All stations sense the medium IDLE, wait DIFS ({self.DIFS} slots), "
              f"then pick a random backoff in [0, {Station.CW_MIN - 1}]:")
        for st in self.stations:
            b = st.choose_backoff(self.rng)
            print(f"   {st.name}: backoff = {b}")
        self.slot = self.DIFS

        print(f"\n Counting down (one idle slot = -1 on every pending backoff;")
        print(f" the first to reach 0 transmits; ties collide):")

        safety = 0
        while not all(s.done for s in self.stations) and safety < 500:
            safety += 1
            contenders = [s for s in self.stations if not s.done]

            # Which contenders are ready to transmit THIS slot (backoff == 0)?
            ready = [s for s in contenders if s.backoff == 0]

            if len(ready) == 0:
                # Nobody is at zero -> an ordinary idle slot: everyone counts down.
                states = "  ".join(f"{s.name}={s.backoff}" for s in contenders)
                print(f"    slot {self.slot:>3}: idle, count down    [{states}]")
                for s in contenders:
                    s.backoff -= 1
                self.slot += 1

            elif len(ready) == 1:
                # Exactly one winner -> a successful transmission.
                self._successful_exchange(ready[0])
                # Advance time past the busy period (others were frozen).
                self.slot += self.TX_SLOTS + self.DIFS

            else:
                # Two or more at zero -> collision + exponential backoff.
                self._collision(ready)
                self.slot += self.JAM_SLOTS + self.DIFS

        # --------------------------------------------------------------------
        print("\n" + _line("="))
        print(" CSMA/CA COMPLETE")
        print(_line("="))
        for s in self.stations:
            print(f"  {s.name}: delivered its frame after {s.collisions} collision(s), "
                  f"final CW={s.cw}")
        print(f"  Total collisions on the medium : {self.total_collisions}")
        print(f"  All stations transmitted?      : "
              f"{'YES ✓' if all(s.done for s in self.stations) else 'NO ✗'}")
        assert all(s.done for s in self.stations)
        return self.wire_events


# ------------------------------------------------------------------------------
# Stand-alone demo: `python3 csma_ca.py`
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Scripted backoffs chosen so the episode shows, in order:
    #   1) a collision between A and C (both pick values that hit 0 together),
    #   2) binary exponential backoff for A and C,
    #   3) B transmitting alone while A and C are frozen,
    #   4) C then A transmitting alone afterwards.
    A = Station("A", "02:00:00:00:00:01", scripted_backoffs=[1, 5])
    B = Station("B", "02:00:00:00:00:02", scripted_backoffs=[3])
    C = Station("C", "02:00:00:00:00:03", scripted_backoffs=[1, 4])
    sim = CSMACASimulation([A, B, C], use_rts_cts=True)
    sim.run()
