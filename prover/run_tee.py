"""Tier 1 + tier 2: the simulated enclave labels and signs, then the TEE circuit is proved.
Run with the SenseCLLM venv (Presidio):  ~/Repos/selencllm_edge/venv/bin/python prover/run_tee.py "text" [mask]
Policy mask bits 8-11 forbid PERSON, LOCATION, NRP, OTHER_ID respectively."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prover"))
sys.path.insert(0, str(ROOT / "tee-sim"))
import enclave  # noqa: E402
import run as prover  # noqa: E402

ALL_ON_TEE = prover.ALL_ON | (0b1111 << 8)


def run_tee(text, n=256, mask=ALL_ON_TEE, prove=True):
    att = enclave.attest(text, n)
    res = prover.run(text, n, mask, prove=prove, tee=att)
    res.update({"sem": att["sem"], "found": att["found"], "ner_s": att["ner_s"], "sign_s": att["sign_s"]})
    return res


if __name__ == "__main__":
    mask = int(sys.argv[2]) if len(sys.argv) > 2 else ALL_ON_TEE
    print(json.dumps(run_tee(sys.argv[1], mask=mask)))
