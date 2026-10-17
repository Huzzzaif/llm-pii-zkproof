"""Tier-2 (enclave) cost: NER, signing, witness, prove, verify, gates at N=256.
    ~/Repos/selencllm_edge/venv/bin/python scripts/bench_tee.py -> eval/results/bench_tee.json"""
import json
import statistics as st
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prover"))
sys.path.insert(0, str(ROOT / "tee-sim"))
from run_tee import run_tee  # noqa: E402

TEXT = ("Thanks for reaching out. Your request has been received and a member of our team will "
        "follow up within two business days. In the meantime, please review the attached guide. ")[:230]
RUNS = 10

if __name__ == "__main__":
    cdir = ROOT / "circuits" / "zkpriv_tee_n256"
    subprocess.run(["nargo", "compile"], cwd=cdir, check=True, capture_output=True)
    g = subprocess.run(["bb", "gates", "-b", str(cdir / "target" / "zkpriv_tee_n256.json")],
                       capture_output=True, text=True, check=True).stdout
    gates = json.loads(g[g.index("{"):])["functions"][0]["circuit_size"]
    runs = [run_tee(TEXT) for _ in range(RUNS)]
    assert all(r["outcome"] == "verified" for r in runs), runs
    med = lambda k: round(st.median(r[k] for r in runs), 4)  # noqa: E731
    out = {"N": 256, "gates": gates, "runs": RUNS, "ner_s": med("ner_s"), "sign_s": med("sign_s"),
           "witness_s": med("witness_s"), "prove_s": med("prove_s"), "verify_s": med("verify_s"),
           "proof_bytes": runs[0]["proof_bytes"], "prove_peak_mib": max(r["prove_peak_mib"] for r in runs)}
    (ROOT / "eval/results/bench_tee.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out))
