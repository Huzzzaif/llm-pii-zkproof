"""Prove and verify ZKPriv statements with nargo + bb (UltraHonk), with timings.

    python3 prover/run.py "text of the LLM response" [--mask 127] [--n 256]

Writes Prover.toml, runs `nargo execute` (witness), `bb prove`, `bb write_vk`,
`bb verify`, and prints a JSON line with timings, proof size and the outcome.
A response containing forbidden PII fails at witness generation: no proof can
be produced, which is the property the paper claims.
"""
import argparse
import json
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALL_ON = (1 << 14) - 1  # thirteen detectors (bits 0-12) + ascii_only (bit 13): strict policy
STANDARD = ALL_ON & ~(1 << 4) & ~(1 << 6)  # standard policy: no generic date detectors (dob stays)
TARGET = ["-t", "noir-recursive"]  # Poseidon2 transcript, zero-knowledge UltraHonk


def circuit_dir(n: int, tee: bool = False) -> Path:
    if tee:
        return ROOT / "circuits" / f"zkpriv_tee_n{n}"
    return ROOT / "circuits" / ("zkpriv" if n == 256 else f"zkpriv_n{n}")


def prover_toml(text: bytes, n: int, mask: int, version: int, pid: int, rho: int, extra=None) -> str:
    if len(text) > n:
        raise ValueError(f"response is {len(text)} bytes; circuit holds {n}")
    y = list(text) + [0] * (n - len(text))
    return (
        f"y = {json.dumps([str(b) for b in y])}\n"
        f'len = "{len(text)}"\n'
        f'rho = "{rho}"\n'
        f'policy_mask = "{mask}"\n'
        f'policy_version = "{version}"\n'
        f'pid = "{pid}"\n'
    ) + "".join(
        f"{k} = {json.dumps([str(x) for x in v]) if isinstance(v, list) else json.dumps(str(v))}\n"
        for k, v in (extra or {}).items()
    )


def sh(cmd, cwd):
    t = time.perf_counter()
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r, time.perf_counter() - t


def run(text: str, n: int = 256, mask: int = ALL_ON, version: int = 1, prove: bool = True,
        tee=None) -> dict:
    """tee: the enclave's attestation dict (tier 2); None proves tier 1 only."""
    cdir = circuit_dir(n, tee is not None)
    name = cdir.name if tee is not None else f"zkpriv_n{n}"
    if tee is not None:
        pid, rho = tee["pid"], tee["rho"]
        extra = {k: tee[k] for k in ("sem", "sig", "pk_x", "pk_y")}
    else:
        pid, rho, extra = secrets.randbits(128), secrets.randbits(250), None
    (cdir / "Prover.toml").write_text(prover_toml(text.encode("utf-8"), n, mask, version, pid, rho, extra))
    res = {"n": n, "len": len(text.encode()), "mask": mask}
    r, t = sh(["nargo", "execute", name], cdir)
    res["witness_s"] = round(t, 3)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().splitlines()
        res["outcome"] = "refused"
        res["reason"] = next((l for l in msg if "policy violation" in l or "assert" in l.lower()), msg[-1] if msg else "")
        return res
    res["outcome"] = "witness_ok"
    if not prove:
        return res
    tgt = cdir / "target"
    out = tgt / "proof_out"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    bytecode, witness = str(tgt / f"{name}.json"), str(tgt / f"{name}.gz")
    # The verification key depends only on the circuit: compute it once and cache it.
    vkdir = tgt / "vk_cache"
    if not (vkdir / "vk").exists():
        vkdir.mkdir(exist_ok=True)
        r, t = sh(["bb", "write_vk", "-b", bytecode, "-o", str(vkdir)] + TARGET, cdir)
        if r.returncode != 0:
            res["outcome"] = "vk_error"
            res["reason"] = r.stderr[-500:]
            return res
    r, t = sh(["/usr/bin/time", "-l", "bb", "prove", "-b", bytecode, "-w", witness, "-o", str(out),
               "-k", str(vkdir / "vk")] + TARGET, cdir)
    for line in r.stderr.splitlines():
        if "maximum resident set size" in line:
            res["prove_peak_mib"] = round(int(line.split()[0]) / 2**20, 1)
    if r.returncode != 0:
        res["outcome"] = "prove_error"
        res["reason"] = r.stderr[-500:]
        return res
    res["prove_s"] = round(t, 3)
    proof = out / "proof"
    res["proof_bytes"] = proof.stat().st_size
    r, t = sh(["bb", "verify", "-k", str(vkdir / "vk"), "-p", str(proof), "-i", str(out / "public_inputs")] + TARGET, cdir)
    res["verify_s"] = round(t, 3)
    res["outcome"] = "verified" if r.returncode == 0 else "verify_failed"
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("text")
    ap.add_argument("--n", type=int, default=256)
    ap.add_argument("--mask", type=int, default=ALL_ON)
    ap.add_argument("--no-prove", action="store_true")
    a = ap.parse_args()
    out = run(a.text, a.n, a.mask, prove=not a.no_prove)
    print(json.dumps(out))
    sys.exit(0 if out["outcome"] in ("verified", "witness_ok", "refused") else 1)
