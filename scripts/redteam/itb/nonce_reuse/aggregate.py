#!/usr/bin/env python3
"""Aggregate the nonce-reuse probe JSON records into a compact table.

Reads every *.json under ~/scratch/redteam/nonce_reuse/ (override via
REDTEAM_NONCE_REUSE_OUTPUT_DIR) and prints one per-layer summary line.
Attacker-visible only — consumes only the emitted JSON records, no Go
test state.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def find_records(root: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not root.exists():
        print(f"[aggregate] no records at {root}", file=sys.stderr)
        return out
    for p in sorted(root.glob("*.json")):
        try:
            out[p.stem] = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            print(f"[aggregate] {p}: {exc}", file=sys.stderr)
    return out


def fmt_cells_a(rec: dict) -> str:
    lines = []
    for cell in rec.get("cells", []):
        lines.append(
            f"  size={cell['plaintext_size']:>4} shape={cell['shape']:<14} "
            f"N={cell['pairs']:>3} chi2_uniform_df255={cell['chi2_uniform_df255']:>10.1f} "
            f"KL(bits)={cell['kl_from_uniform_bits']:>9.5f} "
            f"byte_equal={cell['byte_equal_rate']:.5f} "
            f"({cell['vs_1_over_256_floor']:.2f}x floor)"
        )
    return "\n".join(lines)


def fmt_cells_akpa(rec: dict) -> str:
    lines = []
    for cell in rec.get("cells", []):
        lines.append(
            f"  size={cell['plaintext_size']:>4} shape={cell['shape']:<14} "
            f"region={cell['region']} pairs={cell['pairs']} probe={cell['probe_pixels']} "
            f"max_matches={cell['max_matches_across_startPixels']:>2} "
            f"full_anchor_avg={cell['avg_startPixels_fully_anchoring']:.2f}"
        )
    return "\n".join(lines)


def fmt_region_list(rec: dict, keys: list[tuple[str, str]]) -> str:
    lines = []
    for row in rec.get("per_region", []):
        parts = []
        for label, key in keys:
            v = row.get(key, "?")
            if isinstance(v, float):
                parts.append(f"{label}={v:.3f}")
            else:
                parts.append(f"{label}={v}")
        lines.append("  " + " ".join(parts))
    return "\n".join(lines)


def fmt_crossmsg(rec: dict) -> str:
    lines = []
    for tag in ("regime_A_no_peek", "regime_B_startpixel_peek", "regime_B_prime_mask_oracle_peek"):
        r = rec.get(tag, {})
        lines.append(
            f"  {tag}: matched={r.get('match_bytes','?')}/{r.get('total_bytes','?')} "
            f"rate={r.get('match_rate', 0):.4f}"
        )
    bp = rec.get("regime_B_prime_mask_oracle_peek", {})
    if "content_match_bytes" in bp:
        lines.append(
            f"  regime_B_prime split: content={bp['content_match_bytes']}/{bp['content_total_bytes']} "
            f"rate={bp.get('content_match_rate', 0):.4f}; code byte + interlock-nonce fragment="
            f"{bp['head_match_bytes']}/{bp['head_total_bytes']} rate={bp.get('head_match_rate', 0):.4f}"
        )
    return "\n".join(lines)


def main() -> None:
    root = Path(os.environ.get(
        "REDTEAM_NONCE_REUSE_OUTPUT_DIR",
        str(Path.home() / "scratch" / "redteam" / "nonce_reuse"),
    ))
    records = find_records(root)
    if not records:
        print("no records — did you run `go test -tags redteam -run TestRedTeamNonceReuse ./`?")
        sys.exit(1)

    print("=" * 78)
    print("Nonce-Reuse re-verification (shipped barrier, FNV-1a on all 8 seeds)")
    print("=" * 78)

    if "layer_a_histogram" in records:
        print("\n[Layer A] Byte-histogram on C1 XOR C2 (attacker-visible bytes only)")
        print(fmt_cells_a(records["layer_a_histogram"]))

    if "layer_a_naive_kpa" in records:
        print("\n[Layer A'] Naive Crib KPA constraint match (interlock ignored)")
        print(fmt_cells_akpa(records["layer_a_naive_kpa"]))

    if "layer_b_random_floor" in records:
        print("\n[Layer B random floor] (sp peek only, random plaintext pair)")
        print(fmt_region_list(records["layer_b_random_floor"], [
            ("region", "region"),
            ("pixels", "region_pixels"),
            ("any_np_r", "pixels_with_at_least_1_np_r_admitting_allzero"),
            ("mean_cand", "mean_np_r_candidates_per_pixel"),
        ]))

    if "layer_b_quiet_chunk" in records:
        print("\n[Layer B quiet-chunk] (sp peek only, near-identical plaintext pair)")
        print(fmt_region_list(records["layer_b_quiet_chunk"], [
            ("region", "region"),
            ("pixels", "region_pixels"),
            ("quiet_cands", "quiet_candidate_pixels"),
            ("fully_quiet", "fully_quiet_pixels_all56_np_r_admit"),
            ("log2_amb", "avg_log2_np_r_candidates_on_quiet_pixels"),
        ]))

    if "layer_b_mask_oracle_peek" in records:
        print("\n[Layer B' mask-oracle UPPER BOUND] (sp peek + mask peek; NOT attacker-realistic)")
        print(fmt_region_list(records["layer_b_mask_oracle_peek"], [
            ("region", "region"),
            ("probed", "pixels_probed_within_deterministic_prefix"),
            ("unique_np_r", "pixels_with_unique_np_r"),
            ("multi", "pixels_with_multiple_np_r_candidates"),
            ("zero", "pixels_with_zero_np_r_candidates"),
        ]))

    if "layer_c_fnv_algebraic_precondition" in records:
        print("\n[Layer C] FNV-1a algebraic recovery precondition (attacker-realistic)")
        print(fmt_region_list(records["layer_c_fnv_algebraic_precondition"], [
            ("region", "region"),
            ("pixels", "region_pixels"),
            ("unique_recovered", "pixels_with_unique_np_r"),
            ("any_recovered", "pixels_with_at_least_1_np_r"),
        ]))

    if "layer_d_multi_pair" in records:
        print("\n[Layer D] N=30 nonce-reuse ciphertexts, per-position distinct-value dist")
        print(fmt_region_list(records["layer_d_multi_pair"], [
            ("region", "region"),
            ("bytes", "region_body_bytes"),
            ("mean_dist", "mean_distinct_byte_values_per_position"),
            ("min", "min_distinct_byte_values_per_position"),
            ("le2", "positions_distinct_le_2"),
            ("ge17", "positions_distinct_ge_17"),
        ]))

    if "cross_message_decrypt" in records:
        print("\n[Cross-message decrypt] recover P3 bytes from (C1, C2, P1, P2, C3)")
        print(fmt_crossmsg(records["cross_message_decrypt"]))

    print("\n" + "=" * 78)
    print_verdict(records)


def print_verdict(records: dict[str, dict]) -> None:
    cm = records.get("cross_message_decrypt")
    if cm is None:
        print("Verdict: no cross_message_decrypt record — nothing to conclude.")
        return
    realistic = [cm.get(t, {}) for t in ("regime_A_no_peek", "regime_B_startpixel_peek")]
    real_bytes = sum(int(r.get("match_bytes", 0)) for r in realistic)
    bp = cm.get("regime_B_prime_mask_oracle_peek", {})
    bp_match = int(bp.get("match_bytes", 0))
    bp_total = int(bp.get("total_bytes", 0))
    bp_rate = float(bp.get("match_rate", 0))

    print(f"Attacker-realistic verdict (regimes A and B — no mask peek): {real_bytes} bytes of P3")
    print("recovered under Full KPA + nonce reuse against the always-on barrier.")
    print(f"Mask-oracle upper bound (regime B'): {bp_match}/{bp_total} bytes of the")
    print(f"deterministic prefix recovered (rate {bp_rate:.4f}).")
    lb = records.get("layer_b_mask_oracle_peek")
    if lb is not None:
        rows = lb.get("per_region", [])
        probed = sum(int(r.get("pixels_probed_within_deterministic_prefix", 0)) for r in rows)
        unique = sum(int(r.get("pixels_with_unique_np_r", 0)) for r in rows)
        multi = sum(int(r.get("pixels_with_multiple_np_r_candidates", 0)) for r in rows)
        zero = sum(int(r.get("pixels_with_zero_np_r_candidates", 0)) for r in rows)
        print(f"Layer B' pixels probed={probed}: unique={unique} multi={multi} zero={zero};")
        print("the interlock-nonce fragment pixels carry a zero XOR under the forced nonce")
        print("collision and are expected among the multi-candidate pixels.")
    if real_bytes == 0 and bp_match > 0:
        print("The barrier's closure lives in the mask secrecy — not in any per-pixel")
        print("obfuscation the demasker's Layer 1 could route around.")
    else:
        print(f"Unexpected outcome: realistic={real_bytes} mask-oracle={bp_match}.")
        print("Re-examine the probes before drawing a verdict.")


if __name__ == "__main__":
    main()
