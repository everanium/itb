#!/usr/bin/env python3
"""Structured KEY RECOVERY on the LO LANE (discard on) of standalone
AES-ITB-128, r = 1 — the observable ITB's encoder exposes.

integral_aesitb128.py / keyrecover_r2.py bound the lo-lane key recovery at
r = 1 by the hi-lane enumeration cost of the one-pair inversion (2^64 P^-1
evaluations). That bound is for the INVERSION engine only. This script
measures a different engine on the same observable: a last-round peel on
the two visible columns followed by a per-byte constancy search over a
Λ-set — the aes2r-style structured recovery, ported to the pre-whitened
public permutation.

Construction at the one-block lab shape (data <= 15 bytes, pad byte 0x01
in slot 15; keyrecover_r2.py uses the same DATA_LEN = 15):

    s0  = K ⊕ pad(data)            K = fixedKey ⊕ (LE64(seed0) ‖ LE64(seed1))
    s1  = MC(SR(SB(s0))) ⊕ RC0
    s2  = MC(SR(SB(s1))) ⊕ RC0
    out = MC(SR(SB(s2))) ⊕ RC1     lo lane = out[0:8] = columns 0, 1

Engine (per Λ-set active in data byte b, 256 chosen texts):

  1. Peel. MC^-1 and AddRoundKey are column-local, so
     MC^-1(out_col ⊕ RC1_col) for columns 0 and 1 gives eight bytes of
     SR(SB(s2)); SB^-1 of those is s2 at the eight positions
     {0, 5, 10, 15, 4, 9, 14, 3} (column-major s[4·col + row]) — exactly,
     no guess.
  2. Shape of every such byte over the Λ-set. After round 1 the single
     active input byte b (row r_b, column col_b) lands in column
     c1 = (col_b − r_b) mod 4 with every row affine in one variable
     w = S(K[b] ⊕ v): s1[4·c1 + j] = M[j][r_b]·w ⊕ const_j. ShiftRows of
     round 2 puts one active byte in every column — column c takes row
     j_c = (c1 − c) mod 4 — so
         s2[4·c + i] = M[i][j_c] · S( M[j_c][r_b] · S(K[b] ⊕ v) ⊕ c_c ) ⊕ e_{c,i}
     with c_c (per column) and e_{c,i} (per byte) unknown constants: 24
     unknown bits per observ