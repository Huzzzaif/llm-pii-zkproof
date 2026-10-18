"""Differential test: compiled DFAs vs independent Python references."""
import json
import random
from pathlib import Path
import sys

from card_dfa import build_card_dfa
from detectors import build_all
from reference import ref_card, ref_regex

ALPHA = b"0123456789-  .@/()+abcXZ.:_\n,TMmthsoADGRBC[]"
SEEDS = [b"123-45-6789", b"a@b.co", b"(555) 123-4567", b"10.0.0.1", b"03/14/1985",
         b"4111 1111 1111 1111", b"378282246310005", b"6011-1111-1111-1117",
         b"March 14, 1985", b"14th of March 1985", b"May/58", b"1960-08-01T00:00", b"Sept. 3 2001",
         b"+44 7894 302408", b"034.5324.2943", b"born on the 7th of March 1988", b"G34800996", b"ACCT-8175175160", b"MRN-315378", b"GB13BARC2218419329536326", b"kjones AT corp DOT com", b"a [at] b [dot] org", b"12345678", b"DOB: May/58", b"Date of birth\n 03/14/1985", b"birthday n 1/2/99", b"+12-66-414-3121", b"0137-79-112-7025", b"mar 2, 1999"]


def main(n=200000, seed=42):
    rng = random.Random(seed)
    dfas = build_all()
    dfas["card"] = build_card_dfa()
    refs = {k: (lambda s, k=k: ref_regex(k, s)) for k in dfas if k != "card"}
    refs["card"] = ref_card
    bad = seeded = pos = 0
    for _ in range(n):
        s = bytes(rng.choice(ALPHA) for _ in range(rng.randint(0, 40)))
        if rng.random() < 0.4:
            s += rng.choice(SEEDS) + bytes(rng.choice(ALPHA) for _ in range(rng.randint(0, 6)))
            seeded += 1
        for k, d in dfas.items():
            got = d.run(s)
            pos += bool(got)
            if got != refs[k](s):
                bad += 1
                if bad <= 10:
                    print("MISMATCH", k, s)
    print(f"{n} strings x {len(dfas)} detectors: {bad} mismatches")
    out = Path(__file__).resolve().parents[2] / "eval" / "results" / "difftest.json"
    out.write_text(json.dumps({"strings": n, "detectors": len(dfas), "decisions": n * len(dfas),
                               "mismatches": bad, "seeded_strings": seeded, "positive_decisions": pos,
                               "seed_fraction": 0.4}, indent=2))
    return bad


if __name__ == "__main__":
    sys.exit(1 if main(int(sys.argv[1]) if len(sys.argv) > 1 else 200000) else 0)
