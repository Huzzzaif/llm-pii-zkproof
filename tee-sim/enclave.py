"""Simulated enclave for ZKPriv tier 2 (semantic PII).

Inside a real deployment this code runs in an attested TEE (e.g. Intel TDX or
an H100 confidential VM) next to the LLM; here it runs as a normal process and
the attestation step is not reproduced. Everything else is real:

1. NER with Presidio (spaCy en_core_web_sm) assigns semantic categories:
     bit 0 PERSON, bit 1 LOCATION, bit 2 NRP (nationality/religion/political),
     bit 3 OTHER_ID (passport, driver licence, bank/IBAN, medical licence, ITIN)
2. The digest p2_hash(com, sem) is computed by the `digest_n{N}` helper circuit,
   so the enclave and the proof hash identically.
3. The enclave signs the digest with its secp256k1 key (ECDSA, low-S).

Run with the SenseCLLM venv, which has Presidio and spaCy installed:
    ~/Repos/selencllm_edge/venv/bin/python tee-sim/enclave.py "text"
"""
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
KEY = ROOT / "tee-sim" / "enclave_key.pem"  # simulated enclave key (gitignored)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

SPACY_MODEL = "en_core_web_sm"  # en_core_web_lg in this venv has missing vectors
SEM_BITS = {"PERSON": 0, "LOCATION": 1, "NRP": 2}
OTHER_ID = {"US_PASSPORT", "US_DRIVER_LICENSE", "US_BANK_NUMBER", "IBAN_CODE", "MEDICAL_LICENSE", "US_ITIN", "UK_NHS"}
_analyzer = None


def analyzer():
    global _analyzer
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        conf = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": SPACY_MODEL}]}
        _analyzer = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=conf).create_engine(),
                                   supported_languages=["en"])
    return _analyzer


def semantic_labels(text: str, threshold: float = 0.5):
    res = analyzer().analyze(text=text, language="en", score_threshold=threshold)
    sem, found = 0, []
    for r in res:
        if r.entity_type in SEM_BITS:
            sem |= 1 << SEM_BITS[r.entity_type]
        elif r.entity_type in OTHER_ID:
            sem |= 1 << 3
        else:
            continue
        found.append((r.entity_type, text[r.start:r.end], round(r.score, 2)))
    return sem, found


def enclave_key():
    if not KEY.exists():
        k = ec.generate_private_key(ec.SECP256K1())
        KEY.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    return serialization.load_pem_private_key(KEY.read_bytes(), password=None)


def pubkey_xy(key):
    nums = key.public_key().public_numbers()
    return list(nums.x.to_bytes(32, "big")), list(nums.y.to_bytes(32, "big"))


def digest(text: bytes, n: int, rho: int, pid: int, sem: int):
    """Run the helper circuit to get (com, digest) exactly as the proof computes them."""
    cdir = ROOT / "circuits" / f"digest_n{n}"
    y = list(text) + [0] * (n - len(text))
    (cdir / "Prover.toml").write_text(
        f"y = {json.dumps([str(b) for b in y])}\nlen = \"{len(text)}\"\nrho = \"{rho}\"\n"
        f"pid = \"{pid}\"\nsem = \"{sem}\"\n")
    r = subprocess.run(["nargo", "execute"], cwd=cdir, capture_output=True, text=True, check=True)
    com, dig = re.findall(r"0x[0-9a-fA-F]+", r.stdout.split("Circuit output:")[-1])[:2]
    return int(com, 16), int(dig, 16)


def sign(dig: int):
    der = enclave_key().sign(dig.to_bytes(32, "big"), ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    if s > SECP256K1_N // 2:  # low-S form
        s = SECP256K1_N - s
    return list(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def attest(text: str, n: int = 256):
    """Everything the enclave hands to the prover for tier 2."""
    b = text.encode("utf-8")
    rho, pid = secrets.randbits(250), secrets.randbits(128)
    t0 = time.perf_counter()
    sem, found = semantic_labels(text)
    t_ner = time.perf_counter() - t0
    com, dig = digest(b, n, rho, pid, sem)
    t1 = time.perf_counter()
    sig = sign(dig)
    t_sign = time.perf_counter() - t1
    px, py = pubkey_xy(enclave_key())
    return {"rho": rho, "pid": pid, "sem": sem, "found": found, "com": hex(com), "sig": sig,
            "pk_x": px, "pk_y": py, "ner_s": round(t_ner, 3), "sign_s": round(t_sign, 4)}


if __name__ == "__main__":
    out = attest(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 256)
    print(json.dumps({k: v for k, v in out.items() if k not in ("sig", "pk_x", "pk_y")}))
