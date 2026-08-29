#!/usr/bin/env python3
"""Autoguess (guess-and-determine) model of ChainHash<2-round-AES>.

Adapts the autoguess AES word-level G&D template (ciphers/AES/aes1kp) to the
ChainHash composition: TWO 2-round-AES calls on the SAME plaintext P, keyed by
K0=seed0 and K1=seed1^ct0 (feed-forward). known = {P, ct1}; target =
{seed0, seed1}. Autoguess --findmin reports the minimal #words to GUESS so the
rest is DETERMINED -> the guess-and-determine complexity of r=2 key recovery.

r=1 (single AES2R, known P+ct0) reproduces aes1kp's mg=10 baseline.
discard ON: only columns 2,3 of ct1 (lo 64 bits = bytes 8..15) are known.
"""
import itertools, os, sys

KEY_SCH = ['K_0_3_3, K_1_3_2, K_1_3_3', 'K_0_3_2, K_1_3_1, K_1_3_2',
           'K_0_3_1, K_1_3_0, K_1_3_1', 'K_0_0_3, K_0_3_0, K_1_3_0',
           'K_0_2_3, K_1_2_2, K_1_2_3', 'K_0_2_2, K_1_2_1, K_1_2_2',
           'K_0_2_1, K_1_2_0, K_1_2_1', 'K_0_2_0, K_0_3_3, K_1_2_0',
           'K_0_1_3, K_1_1_2, K_1_1_3', 'K_0_1_2, K_1_1_1, K_1_1_2',
           'K_0_1_1, K_1_1_0, K_1_1_1', 'K_0_1_0, K_0_2_3, K_1_1_0',
           'K_0_0_3, K_1_0_2, K_1_0_3', 'K_0_0_2, K_1_0_1, K_1_0_2',
           'K_0_0_1, K_1_0_0, K_1_0_1', 'K_0_0_0, K_0_1_3, K_1_0_0']

def emit_aes2r(eqs, pre, pt, R=2):
    K = lambda r, i, j: f'K{pre}_{r}_{i}_{j}'
    X = lambda r, i, j: f'X{pre}_{r}_{i}_{j}'
    W = lambda r, i, j: f'W{pre}_{r}_{i}_{j}'
    for i in range(4):
        for j in range(4):
            eqs.append(f'{pt[4*i+j]}, {K(0,i,j)}, {X(0,i,j)}')      # X0 = P ^ K0
    for r in range(R):
        for i in range(4):
            for j in range(4):
                eqs.append(f'{W(r,i,j)}, {K(r+1,i,j)}, {X(r+1,i,j)}')  # X_{r+1}=W_r^K_{r+1}
        for rel in KEY_SCH:
            eqs.append(rel.replace('K_1', f'K{pre}_{r+1}').replace('K_0', f'K{pre}_{r}'))
        # MDS (SR o MixColumns), branch number 5: any 4 of the 8 -> rest
        cols = [
            [X(r,0,0), X(r,1,1), X(r,2,2), X(r,3,3)] + [W(r,i,0) for i in range(4)],
            [X(r,0,1), X(r,1,2), X(r,2,3), X(r,3,0)] + [W(r,i,1) for i in range(4)],
            [X(r,0,2), X(r,1,3), X(r,2,0), X(r,3,1)] + [W(r,i,2) for i in range(4)],
            [X(r,0,3), X(r,1,0), X(r,2,1), X(r,3,2)] + [W(r,i,3) for i in range(4)],
        ]
        for col in cols:
            for quarter in itertools.combinations(col, 4):
                for el in col:
                    if el not in quarter:
                        eqs.append(','.join(quarter) + ' => ' + el)
    return [X(R, i, j) for i in range(4) for j in range(4)]   # ciphertext words

def build(rounds, discard):
    pt = [f'P_{i}_{j}' for i in range(4) for j in range(4)]
    eqs = []
    ct0 = emit_aes2r(eqs, 'a', pt)
    if rounds == 1:
        known = pt + ct0
        target = [f'Ka_0_{i}_{j}' for i in range(4) for j in range(4)]
        ct_obs = ct0
    else:
        # feed-forward: Kb_0_i_j = seed1_i_j ^ ct0_i_j   (ct0 = Xa_2)
        for i in range(4):
            for j in range(4):
                eqs.append(f'Kb_0_{i}_{j}, S1_{i}_{j}, Xa_2_{i}_{j}')
        ct1 = emit_aes2r(eqs, 'b', pt)
        # discard ON -> only lo 64 bits = bytes 8..15 = columns j in {2,3}
        if discard:
            ct_obs = [f'Xb_2_{i}_{j}' for i in range(4) for j in (2, 3)]
        else:
            ct_obs = ct1
        known = pt + ct_obs
        target = [f'Ka_0_{i}_{j}' for i in range(4) for j in range(4)] + \
                 [f'S1_{i}_{j}' for i in range(4) for j in range(4)]
    body = '#chainhash_aes2r r=%d discard=%s\nconnection relations\n' % (rounds, discard)
    body += '\n'.join(eqs) + '\nknown\n' + '\n'.join(known)
    body += '\ntarget\n' + '\n'.join(target) + '\nend'
    return body

if __name__ == '__main__':
    for rounds in (1, 2):
        for discard in ([False] if rounds == 1 else [False, True]):
            txt = build(rounds, discard)
            fn = f'relationfile_chainhash_r{rounds}_discard{int(discard)}.txt'
            with open(fn, 'w') as f:
                f.write(txt)
            print(f'wrote {fn}  ({len(txt.splitlines())} lines)')
