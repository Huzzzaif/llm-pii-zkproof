"""Benchmarks for the paper (all numbers in the evaluation come from here).

    python3 scripts/bench.py  ->  eval/results/bench.json

A: scaling with response capacity N (all six detectors), 10 prove/verify runs each.
B: gate breakdown at N=256 (no detectors, then each detector alone).
"""
import json
import statistics as st
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prover"))
import run as prover  # noqa: E402

GEN = ROOT / "circuits" / "gen" / "gen_noir.py"
CLEAN = ("Thanks for reaching out. Your request has been received and a member of our team will "
         "follow up within two business days. In the meantime, please review the attached guide. ")
RUNS = 10


def gates(cdir: Path) -> int:
    import shutil
    shutil.rmtree(cdir / "target" / "vk_cache", ignore_errors=True)  # circuit may have changed
    subprocess.run(["nargo", "compile"], cwd=cdir, check=True, capture_output=True)
    name = next((cdir / "target").glob("*.json"))
    out = subprocess.run(["bb", "gates", "-b", str(name)], capture_output=True, text=True, check=True).stdout
    return json.loads(out[out.index("{"):])["functions"][0]["circuit_size"]


def med_iqr(xs):
    q = st.quantiles(xs, n=4)
    return {"median": round(st.median(xs), 4), "q1": round(q[0], 4), "q3": round(q[2], 4)}


def scaling(ns=(64, 128, 256, 512, 1024)):
    rows = []
    for n in ns:
        subprocess.run([sys.executable, str(GEN), str(n)], check=True, capture_output=True)
        cdir = prover.circuit_dir(n)
        g = gates(cdir)
        text = (CLEAN * (n // len(CLEAN) + 1))[: int(n * 0.9)]
        runs = [prover.run(text, n) for _ in range(RUNS)]
        assert all(r["outcome"] == "verified" for r in runs), runs
        row = {
            "N": n, "gates": g, "len": len(text),
            "witness_s": med_iqr([r["witness_s"] for r in runs]),
            "prove_s": med_iqr([r["prove_s"] for r in runs]),
            "verify_s": med_iqr([r["verify_s"] for r in runs]),
            "proof_bytes": runs[0]["proof_bytes"],
            "prove_peak_mib": max(r.get("prove_peak_mib", 0) for r in runs),
        }
        print(json.dumps(row), flush=True)
        rows.append(row)
    return rows


def breakdown(n=256):
    out = {}
    sys.path.insert(0, str(ROOT / "circuits" / "gen"))
    from gen_noir import ORDER
    for tag, dets in [("none", "")] + [(d, d) for d in ORDER]:
        subprocess.run([sys.executable, str(GEN), str(n), dets], check=True, capture_output=True)
        cdir = ROOT / "circuits" / "variants" / f"n{n}_{tag}"
        out[tag] = gates(cdir)
        print(tag, out[tag], flush=True)
    subprocess.run([sys.executable, str(GEN), str(n)], check=True, capture_output=True)
    out["all"] = gates(prover.circuit_dir(n))
    return out


def throughput(n=256, total=24, workers=(1, 2, 4, 8)):
    """Proofs per second with k independent provers in parallel (separate circuit copies)."""
    import shutil
    import time
    from concurrent.futures import ThreadPoolExecutor
    subprocess.run([sys.executable, str(GEN), str(n)], check=True, capture_output=True)
    base = prover.circuit_dir(n)
    gates(base)
    text = (CLEAN * 3)[: int(n * 0.9)]
    prover.run(text, n)  # warm the cached verification key
    copies = []
    for i in range(max(workers)):
        d = ROOT / "circuits" / "variants" / f"tp_{i}"
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(base, d)
        copies.append(d)
    out = {}
    for k in workers:
        def job(i):
            return prover.run(text, n, cdir=copies[i % k])
        t0 = time.perf_counter()
        with ThreadPoolExecutor(k) as ex:
            res = list(ex.map(job, range(total)))
        dt = time.perf_counter() - t0
        assert all(r["outcome"] == "verified" for r in res), res[:2]
        out[str(k)] = {"proofs": total, "seconds": round(dt, 2), "proofs_per_s": round(total / dt, 2)}
        print("throughput", k, out[str(k)], flush=True)
    return out


if __name__ == "__main__":
    import platform
    hw = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip()
    res = {"hardware": hw, "macos": platform.mac_ver()[0], "runs": RUNS,
           "nargo": subprocess.run(["nargo", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
           "bb": subprocess.run(["bb", "--version"], capture_output=True, text=True).stdout.strip(),
           "breakdown_n256": breakdown(), "scaling": scaling(), "throughput_n256": throughput()}
    (ROOT / "eval/results").mkdir(exist_ok=True)
    (ROOT / "eval/results/bench.json").write_text(json.dumps(res, indent=2))
    print("wrote eval/results/bench.json")
