"""Presidio baseline and tier-2 (semantic) recall, on the same records and with the
same per-value isolation protocol as detector_eval.py.

  * Structured types: does Presidio flag each value (span overlap, mapped entity)?
    This is the baseline for the in-circuit detectors.
  * Semantic types (tier 2): names (GIVENNAME/SURNAME/name) -> PERSON,
    places (CITY/STREET) -> LOCATION, using the enclave's own analyzer.

    ~/Repos/selencllm_edge/venv/bin/python eval/presidio_eval.py -> eval/results/presidio_eval.json
"""
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tee-sim"))
import enclave  # noqa: E402

NEUTRAL = "X"
STRUCT = {"ssn": {"US_SSN"}, "email": {"EMAIL_ADDRESS"}, "phone_us": {"PHONE_NUMBER"},
          "ipv4": {"IP_ADDRESS"}, "date": {"DATE_TIME"}, "card": {"CREDIT_CARD"}}
AI4P = {"SOCIALNUM": "ssn", "TAXNUM": "ssn", "EMAIL": "email", "TELEPHONENUM": "phone_us",
        "CREDITCARDNUMBER": "card", "DATEOFBIRTH": "date",
        "GIVENNAME": "PERSON", "SURNAME": "PERSON", "CITY": "LOCATION", "STREET": "LOCATION"}
SYNTH = {"ssn": "ssn", "email": "email", "phone": "phone_us", "cc": "card", "ip": "ipv4", "dob": "date",
         "name": "PERSON"}


def scrub(text, values, keep=None):
    for v in sorted(set(values), key=len, reverse=True):
        if v != keep:
            text = text.replace(v, NEUTRAL)
    return text


BASE_T, SEM_T = 0.0, 0.5  # Presidio's default threshold for the baseline; enclave threshold for tier 2


def flagged(text, value, kind):
    i = text.find(value)
    if i < 0:
        return False
    j = i + len(value)
    want = STRUCT.get(kind, {kind})
    th = BASE_T if kind in STRUCT else SEM_T
    for r in enclave.analyzer().analyze(text=text, language="en", score_threshold=th):
        if r.entity_type in want and r.start < j and r.end > i:
            return True
    return False


def any_flag(text, kinds):
    ents = {e for k in kinds for e in STRUCT.get(k, {k})}
    return any(r.entity_type in ents for r in enclave.analyzer().analyze(text=text, language="en", score_threshold=BASE_T))


def evaluate(records, typed):
    hit, tot = defaultdict(int), defaultdict(int)
    for r in records:
        for v, kind in typed(r):
            iso = scrub(r["text"], r["pii_values"], keep=v)
            tot[kind] += 1
            hit[kind] += flagged(iso, v, kind)
    structured = list(STRUCT)
    in_scope = [r for r in records if any(k in STRUCT for _, k in typed(r))]
    refused = sum(any_flag(r["text"], structured) for r in in_scope)
    false_ref = sum(any_flag(scrub(r["text"], r["pii_values"]), structured) for r in records)
    return {
        "per_type": {k: {"recall": round(hit[k] / tot[k], 3), "hits": hit[k], "n": tot[k]} for k in sorted(tot)},
        "refusal_rate_in_scope": round(refused / max(1, len(in_scope)), 3),
        "false_refusal_rate_scrubbed": round(false_ref / len(records), 3),
    }


def ai4p(r):
    for v, t in zip(r["pii_values"], r["pii_types"]):
        if t in AI4P:
            yield v, AI4P[t]


def synth(r):
    for k, kind in SYNTH.items():
        v = r.get("pii_payload", {}).get(k)
        if v and v in r["text"]:
            yield v, kind


if __name__ == "__main__":
    t0 = time.time()
    out = {
        "analyzer": f"Presidio + spaCy {enclave.SPACY_MODEL}; structured baseline at Presidio default threshold {BASE_T}, semantic (tier 2) at {SEM_T}",
        "ai4privacy_500": evaluate(json.loads((ROOT / "eval/data/ai4privacy_500.json").read_text()), ai4p),
        "synth_500": evaluate(json.loads((ROOT / "eval/data/synth_500.json").read_text()), synth),
    }
    out["seconds"] = round(time.time() - t0, 1)
    (ROOT / "eval/results/presidio_eval.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
