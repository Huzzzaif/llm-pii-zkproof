"""Tier-2 soundness checks: a provider that lies about the enclave's labels, tampers
with the signature, or uses a different key must not be able to produce a proof.

    ~/Repos/selencllm_edge/venv/bin/python eval/tee_soundness.py  ->  eval/results/tee_soundness.json
"""
import copy
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prover"))
sys.path.insert(0, str(ROOT / "tee-sim"))
import enclave  # noqa: E402
import run as prover  # noqa: E402
from run_tee import ALL_ON_TEE  # noqa: E402

TEXT = "Dr. Maria Gonzalez will see you in Chicago next week."
CLEAN = "Your appointment is confirmed for next Tuesday."


def attempt(label, text, att, mask=ALL_ON_TEE):
    r = prover.run(text, 256, mask, prove=False, tee=att)
    return {"case": label, "outcome": r["outcome"], "reason": r.get("reason", "")}


if __name__ == "__main__":
    att = enclave.attest(TEXT)
    rows = [attempt("honest labels, names forbidden", TEXT, att)]

    lie = copy.deepcopy(att)
    lie["sem"] = 0  # provider claims no names were found
    rows.append(attempt("provider zeroes the labels", TEXT, lie))

    bad = copy.deepcopy(att)
    bad["sig"][5] ^= 1
    rows.append(attempt("signature bit flipped", TEXT, bad, mask=prover.ALL_ON))

    other = ec.generate_private_key(ec.SECP256K1())
    wrong = copy.deepcopy(att)
    wrong["pk_x"], wrong["pk_y"] = enclave.pubkey_xy(other)
    rows.append(attempt("verification key of another enclave", TEXT, wrong, mask=prover.ALL_ON))

    swap = enclave.attest(CLEAN)  # valid attestation for a *different* response
    rows.append(attempt("attestation reused for another response", TEXT, swap, mask=prover.ALL_ON))

    ok = all(r["outcome"] == "refused" for r in rows)
    for r in rows:
        print(f"{r['case']:42s} {r['outcome']:10s} {r['reason']}")
    (ROOT / "eval/results/tee_soundness.json").write_text(json.dumps({"all_refused": ok, "cases": rows}, indent=2))
    print("all attacks refused:", ok)
