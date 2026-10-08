---
title: "Hardware - signals"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Hardware Signals Writeup

The WAV file is an SSTV transmission, not packet radio.

The giveaway is the VIS/header pattern at the start of the audio:

- `1900 Hz` leader
- `1200 Hz` break
- `1900 Hz` leader
- VIS bits around `1100/1300 Hz`

Decoding the VIS bits gives decimal `95`, which corresponds to `PD120`. That also matches the total duration of the file: about `126 s`, which is the expected PD120 transmission time used in ISS SSTV events.

## Reconstruction

PD120 sends image data as line pairs:

- `20 ms` sync pulse at `1200 Hz`
- `2.08 ms` porch at `1500 Hz`
- `121.6 ms` `Y0`
- `121.6 ms` `R-Y`
- `121.6 ms` `B-Y`
- `121.6 ms` `Y1`

I wrote a decoder in [solve_pd120.py](/home/kali/HTB/HARDWARE_CHALLENGES/hardware_signals/solve_pd120.py) that:

1. Loads `Signal.wav`
2. Computes instantaneous frequency with a Hilbert transform
3. Detects the long `1200 Hz` PD120 sync pulses
4. Samples each PD120 component for all `248` line pairs
5. Rebuilds the `640x496` RGB image and saves it as `decoded_pd120.png`

Run:

```bash
python3 solve_pd120.py
```

## Flag

The recovered image clearly shows the flag:

```text
HTB{5l0w-5c4n_7313v1510n_h4m_r4d10_h4ck3r}
```
