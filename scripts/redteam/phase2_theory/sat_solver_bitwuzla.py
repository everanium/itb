#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bitwuzla-via-subprocess SMT-LIB2 solver helper.

Used by SAT calibration scripts that build a QF_BV formula in Z3 and
want to ship it to Bitwuzla's CDCL(T) backend for a HARD wall-clock
budget enforced at the OS level (`subprocess.run` timeout). Z3's
in-process `set('timeout', ms)` only halts CDCL, not the bit-blasting
or preprocess phases, which on FNV-chain / MD5-chain instances tend
to dominate wall-clock and can ignore the in-process timer. The
subprocess boundary is the only mechanism that reliably caps every
solver phase.

Pattern (consumer side):

    import z3
    solver = z3.Solver()
    solver.add(...)                # standard Z3 constraint building
    smt2 = solver.to_smt2()         # emits "(check-sat)" already
    status, values = solve_via_bitwuzla(
        smt2,
        seed_var_names=["s_lo_0", "s_lo_1", ...],
        timeout_sec=300,
    )

`bitwuzla` CLI (>= 0.5.0) must be on PATH (`yay -S bitwuzla` on Arch).

A near-identical private copy of this routine lives inline in
scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py for Phase 2g
reproducibility (any drift in that file would break the published
Phase 2g result). This shared module is for newer callers that are
free to take a dependency on the helper.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from typing import List, Sequence, Tuple


def solve_via_bitwuzla(
    smt2_text: str,
    seed_var_names: Sequence[str],
    timeout_sec: int,
    var_bit_width: int = 64,
    quiet: bool = False,
) -> Tuple[str, List[int]]:
    """Pipe an SMT-LIB2 dump through the Bitwuzla CLI, parse status + model.

    The supplied ``smt2_text`` is expected to be Z3's
    ``solver.to_smt2()`` output, which already terminates with
    ``(check-sat)``. Per-variable ``(get-value ...)`` queries for
    every name in ``seed_var_names`` are appended after it.

    Returns ``(status, values)`` where:
        * ``status`` is one of ``"sat"``, ``"unsat"``, ``"timeout"``,
          ``"unknown"``;
        * ``values`` is one ``int`` per name in ``seed_var_names``,
          masked to ``var_bit_width`` bits, when ``status == "sat"``;
          empty list otherwise.

    The subprocess wall-clock timeout is ``timeout_sec + 60`` seconds
    (outer safety margin); Bitwuzla itself receives ``--time-limit``
    in milliseconds so it can self-terminate cleanly. Both bounds
    matter: ``--time-limit`` lets Bitwuzla emit clean diagnostics;
    the outer timeout is the hard floor.
    """
    mask = (1 << var_bit_width) - 1

    # Z3's `to_smt2()` already appends `(check-sat)`. We append only
    # `(get-value ...)` queries after it (and an optional `(exit)`).
    # Double `(check-sat)` causes Bitwuzla to evaluate get-value
    # against a stale model state.
    value_queries = "\n".join(f"(get-value ({name}))" for name in seed_var_names)
    smt2_full = smt2_text.rstrip() + "\n" + value_queries + "\n(exit)\n"

    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False) as fh:
        fh.write(smt2_full)
        smt2_path = fh.name

    try:
        proc = subprocess.run(
            ["bitwuzla",
             "--produce-models",
             "--print-model",
             "--time-limit", str(timeout_sec * 1000),
             smt2_path],
            capture_output=True, text=True,
            timeout=timeout_sec + 60,
        )
    except subprocess.TimeoutExpired:
        return ("timeout", [])
    finally:
        try:
            os.unlink(smt2_path)
        except Exception:
            pass

    out = proc.stdout
    if not quiet and proc.returncode not in (0, 10, 20):
        # 10 = sat, 20 = unsat per SMT-LIB convention
        print(
            f"[bitwuzla] exit={proc.returncode} stderr={proc.stderr[:200]!r}",
            file=sys.stderr,
        )
    first_line = (out.splitlines() or [""])[0].strip()
    if first_line == "sat":
        status = "sat"
    elif first_line == "unsat":
        status = "unsat"
    elif first_line in ("timeout", "unknown"):
        status = first_line
    else:
        status = "unknown"

    model_values: List[int] = []
    if status == "sat":
        for name in seed_var_names:
            # Bitwuzla output for `(get-value (s_lo_0))` is
            # `((s_lo_0 #x...hexdigits..))` with hex chars, OR
            # `((s_lo_0 #b...bits...))`.
            m = re.search(
                rf"\({re.escape(name)}\s+(#x[0-9a-fA-F]+|#b[01]+)\s*\)", out
            )
            if not m:
                model_values.append(0)
                continue
            tok = m.group(1)
            if tok.startswith("#x"):
                model_values.append(int(tok[2:], 16) & mask)
            else:
                model_values.append(int(tok[2:], 2) & mask)
    return (status, model_values)
