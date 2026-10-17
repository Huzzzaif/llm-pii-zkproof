"""Agreement test: the compiled Noir circuit (via `nargo execute`) must refuse
exactly the responses the independent Python `re` references flag.

    python3 eval/circuit_agreement.py [n_cases]  ->  eval/results/circuit_agreement.json
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "circuits" / "gen"))
sys.path.insert(0, str(ROOT / "prover"))
from reference import ref_card, ref_regex  # noqa: E402
import run as prover  # noqa: E402

from detectors import PATTERNS  # noqa: E402
NAMES = list(PATTERNS)
ALPHA = "0123456789-  .@/()+abcXZ.:_"
SEEDS = ["born on May 3, 1990", "G34800996", "ACCT-8175175160", "GB13BARC2218419329536326", "kjones AT corp DOT com",
         "+44 7894 302408", "March 14, 1985", "123456789012", "123-45-6789", "a@b.co", "(555) 123-4567", "10.0.0.1", "03/14/1985", "4111 1111 1111 1111",
         "378282246310005", "123 45 678", "4111 1111 1111 1112", "999.1.1.1", "x@y", "1985-13-45"]


def ref_any(s: str) -> bool:
    b = s.encode()
    return any(ref_regex(k, b) for k in NAMES) or ref_card(b)


def cases(n, seed=7):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        s = "".join(rng.choice(ALPHA) for _ in range(rng.randint(1, 60)))
        if rng.random() < 0.5:
            s += rng.choice(SEEDS) + "".join(rng.choice(ALPHA) for _ in range(rng.randint(0, 8)))
        out.append(s[:256])
    return out


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    agree, rows = 0, []
    for s in cases(n):
        r = prover.run(s, prove=False)
        circuit_refused = r["outcome"] == "refused"
        ok = circuit_refused == ref_any(s)
        agree += ok
        if not ok:
            rows.append({"text": s, "circuit": r, "reference_flags": ref_any(s)})
            print("DISAGREE", repr(s), r)
    res = {"cases": n, "agree": agree, "disagreements": rows}
    (ROOT / "eval/results").mkdir(exist_ok=True)
    (ROOT / "eval/results/circuit_agreement.json").write_text(json.dumps(res, indent=2))
    print(f"circuit vs reference: {agree}/{n} agree")
