"""Strict-policy circuit cost across response sizes (Fig. 2, strict line).

The strict policy blocks every date with the generic date detectors, so its
compiled circuit omits the birth-date detector (detection is identical on both
held-out sets, see eval/compare.py system zkpriv_strict_nodob).

    python3 scripts/bench_strict.py  ->  eval/results/bench_strict_scaling.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prover"))
sys.path.insert(0, str(ROOT / "circuits" / "gen"))
sys.path.insert(0, str(ROOT / "scripts"))
import run as prover  # noqa: E402
from bench import CLEAN, RUNS, gates, med_iqr  # noqa: E402
from gen_noir import ORDER, emit  # noqa: E402

STRICT = [d for d in ORDER if d != "dob"]


def main(ns=(64, 128, 256, 512, 1024)):
    rows = []
    for n in ns:
        cdir = ROOT / "circuits" / "variants" / f"strict_n{n}"
        emit(cdir, n, STRICT, pkg=f"zkpriv_n{n}")
        g = gates(cdir)
        text = (CLEAN * (n // len(CLEAN) + 1))[: int(n * 0.9)]
        runs = [prover.run(text, n, cdir=cdir) for _ in range(RUNS)]
        assert all(r["outcome"] == "verified" for r in runs), runs
        row = {"N": n, "gates": g,
               "prove_s": med_iqr([r["prove_s"] for r in runs]),
               "verify_s": round(sorted(r["verify_s"] for r in runs)[RUNS // 2], 4),
               "peak_mib": max(r.get("prove_peak_mib", 0) for r in runs)}
        print(json.dumps(row), flush=True)
        rows.append(row)
    out = ROOT / "eval" / "results" / "bench_strict_scaling.json"
    out.write_text(json.dumps({"detectors": STRICT, "runs": RUNS, "scaling": rows}, indent=2))


if __name__ == "__main__":
    main()
