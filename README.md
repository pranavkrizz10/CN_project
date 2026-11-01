# Complete Data Link Layer — Go-Back-N + Hamming Codes + CSMA/CA (with PyShark)

**End Assignment 8** — a full, working simulation of the data link layer in
Python. It demonstrates, with detailed console output, every required feature:

| Feature (from the assignment) | How it is implemented |
|---|---|
| **Error control** | **Hamming codes** (SECDED): correct any single-bit error, detect any double-bit error |
| **Flow control** | **Go-Back-N** sliding window + cumulative ACKs |
| **Error recovery** | Timeouts and **go-back-N retransmission** |
| **In-order delivery** | Receiver accepts frames strictly in sequence |
| **Multiple access** | **CSMA/CA**: carrier sensing, random + binary-exponential backoff, collision avoidance, RTS/CTS/DATA/ACK |
| **Packet inspection** | Every transmitted frame is written to a real **`.pcap`** and re-read with **PyShark**, which prints the detailed packet content for each feature |

The output clearly shows **the movement of packets, in-order delivery, error
handling and flow control**, exactly as required.

---

## 1. What you need

* **Python 3.8+**
* **Python packages:** `pyshark`, `scapy` → `pip install -r requirements.txt`
* **tshark** (the Wireshark command-line engine that PyShark drives). This is an
  OS program, *not* a pip package:
  * Ubuntu / Debian: `sudo apt-get install -y tshark`
  * macOS (Homebrew): `brew install wireshark`
  * Fedora: `sudo dnf install wireshark-cli`
  * Check it: `tshark --version`

## 2. How to run

```bash
# from inside this folder
pip install -r requirements.txt     # install scapy + pyshark
./run.sh                            # runs the whole demonstration
```

or directly:

```bash
cd src
python3 main.py
```

You can also run each component on its own to see just that part:

```bash
cd src
python3 hamming.py      # Hamming encode/decode self-tests
python3 go_back_n.py    # just the Go-Back-N exchange
python3 csma_ca.py      # just the CSMA/CA contention episode
python3 packet_capture.py   # a tiny PyShark capture/inspection demo
```

The full run writes a real capture file to `output/datalink_capture.pcap`. You
can open it in **Wireshark** too — filter on `eth.type == 0x88b5` to see only
our data-link frames. A reference transcript of the whole program's output is
saved at `output/sample_output.txt`.

---

## 3. Project layout

```
datalink_layer/
├── README.md              <- this file
├── requirements.txt       <- pip dependencies (+ note about tshark)
├── run.sh                 <- one-command launcher
├── src/
│   ├── hamming.py         <- ERROR CONTROL: Hamming SECDED encode/decode
│   ├── frame.py           <- the data link FRAME format (serialize/parse)
│   ├── channel.py         <- the lossy/noisy MEDIUM (injects bit errors & loss)
│   ├── go_back_n.py       <- FLOW CONTROL + ARQ: Go-Back-N sender/receiver
│   ├── csma_ca.py         <- MULTIPLE ACCESS: CSMA/CA with backoff & RTS/CTS
│   ├── packet_capture.py  <- builds the .pcap (Scapy) + PyShark inspection
│   └── main.py            <- entry point: runs all four sections in order
└── output/
    ├── datalink_capture.pcap   <- generated real capture (also opens in Wireshark)
    └── sample_output.txt       <- reference transcript of a full run
```

Every source file is **heavily commented**, explaining both the networking
concept and the code line by line.

---

## 4. How each feature works (quick tour)

### Error control — Hamming codes (`hamming.py`)
Each 4-bit nibble of the payload is expanded into an 8-bit codeword: 4 data
bits, 3 Hamming parity bits (at positions 1, 2, 4) and 1 overall parity bit.
* The parity bits let the receiver compute a **syndrome** that points at the
  exact position of a single flipped bit, which is then corrected.
* The overall parity bit upgrades the code to **SECDED**, so two flipped bits in
  one codeword are **detected** (even though they cannot be corrected).

### Flow control + error recovery — Go-Back-N (`go_back_n.py`)
* The sender may have at most **N** unacknowledged frames in flight (the
  *window*). When the window is full it must wait — that is flow control.
* The receiver sends **cumulative ACKs** (`ack = next expected sequence number`)
  and only accepts frames **in order**; out-of-order or damaged frames are
  dropped.
* If the oldest frame is not acknowledged before its timer expires (because a
  frame or its ACK was lost or corrupted beyond repair), the sender **"goes back
  N"** and retransmits that frame and everything after it.
* A frame hit by a *single-bit* error is repaired by Hamming and **accepted with
  no retransmission**; a frame hit by a *double-bit* error is detected, dropped,
  and **retransmitted**.

### Multiple access — CSMA/CA (`csma_ca.py`)
Several stations share one medium and one access point.
* Each senses the medium, waits a gap (DIFS), then counts down a **random
  backoff** from its contention window.
* If two stations hit zero together they **collide**; each then **doubles its
  contention window** (binary exponential backoff) and retries.
* While another station transmits, waiting stations **freeze** their backoff
  counters and resume afterwards (fairness).
* The winner runs the **RTS → CTS → DATA → ACK** handshake; everyone else sets
  their NAV and stays quiet.

### Packet inspection — PyShark (`packet_capture.py`)
Because the real data link layer *is* Ethernet, each simulated frame is wrapped
in a genuine Ethernet II header (custom EtherType `0x88B5`) with **Scapy** and
written to `output/datalink_capture.pcap`. **PyShark** then re-opens that file
and prints the dissected content of every packet — the Ethernet header it
decoded, the raw bytes, our data-link header, and (for DATA frames) the Hamming
verdict computed on the exact bytes that were captured. This is where the error
control, flow control and multiple-access behaviour is shown at the packet
level.
