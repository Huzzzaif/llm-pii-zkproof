"""Differential test: compiled DFAs vs independent Python references."""
import random
import sys

from card_dfa import build_card_dfa
from detectors import build_all
from reference import ref_card, ref_regex

ALPHA = b"0123456789-  .@/()+abcXZ.:_\n"
SEEDS = [b"123-45-6789", b"a@b.co", b"(555) 123-4567", b"10.0.0.1", b"03/14/1985",
         b"4111 1111 1111 1111", b"378282246310005", b"6011-1111-1111-1117"]


def main(n=200000, seed=42):
    rng = random.Random(seed)
    dfas = build_all()
    dfas["card"] = build_card_dfa()
    refs = {k: (lambda s, k=k: ref_regex(k, s)) for k in dfas if k != "card"}
    refs["card"] = ref_card
    bad = 0
    for _ in range(n):
        s = bytes(rng.choice(ALPHA) for _ in range(rng.randint(0, 40)))
        if rng.random() < 0.4:
            s += rng.choice(SEEDS) + bytes(rng.choice(ALPHA) for _ in range(rng.randint(0, 6)))
        for k, d in dfas.items():
            if d.run(s) != refs[k](s):
                bad += 1
                if bad <= 10:
                    print("MISMATCH", k, s)
    print(f"{n} strings x {len(dfas)} detectors: {bad} mismatches")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main(int(sys.argv[1]) if len(sys.argv) > 1 else 200000) else 0)
