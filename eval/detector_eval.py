"""Detector accuracy of the in-circuit DFAs (identical tables to the Noir circuit).

Per-value recall: for every annotated PII value of an in-scope type, all *other*
annotated values in the record are replaced by a neutral token, and we check
whether the detector for that type fires. Record-level metrics run all six
detectors on the original text (refusal rate) and on a fully scrubbed copy
(false-refusal rate).

    python3 eval/detector_eval.py  ->  eval/results/detector_eval.json
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "circuits" / "gen"))
from card_dfa import build_card_dfa  # noqa: E402
from detectors import build_all  # noqa: E402

DFAS = build_all()
DFAS["card"] = build_card_dfa()

AI4P_MAP = {"SOCIALNUM": "ssn", "TAXNUM": "ssn", "EMAIL": "email", "TELEPHONENUM": "phone_us",
            "CREDITCARDNUMBER": "card", "DATEOFBIRTH": "date"}
SYNTH_KEYS = {"ssn": "ssn", "email": "email", "phone": "phone_us", "cc": "card", "ip": "ipv4", "dob": "date"}
NEUTRAL = "X"


def scrub(text, values, keep=None):
    for v in sorted(set(values), key=len, reverse=True):
        if v != keep:
            text = text.replace(v, NEUTRAL)
    return text


def any_fire(text):
    b = text.encode("utf-8")
    return any(d.run(b) for d in DFAS.values())


def evaluate(records, typed_values):
    hit, tot = defaultdict(int), defaultdict(int)
    misses = defaultdict(list)
    for r in records:
        vals = r["pii_values"]
        for v, det in typed_values(r):
            iso = scrub(r["text"], vals, keep=v)
            ok = DFAS[det].run(iso.encode("utf-8"))
            tot[det] += 1
            hit[det] += ok
            if not ok and len(misses[det]) < 8:
                misses[det].append(v)
    per_type = {k: {"recall": round(hit[k] / tot[k], 3), "hits": hit[k], "n": tot[k], "miss_examples": misses[k]}
                for k in sorted(tot)}
    in_scope = [r for r in records if list(typed_values(r))]
    refused = sum(any_fire(r["text"]) for r in in_scope)
    false_ref = sum(any_fire(scrub(r["text"], r["pii_values"])) for r in records)
    return {
        "per_type": per_type,
        "records": len(records),
        "records_with_in_scope_pii": len(in_scope),
        "refusal_rate_in_scope": round(refused / max(1, len(in_scope)), 3),
        "false_refusal_rate_scrubbed": round(false_ref / len(records), 3),
        "max_len_bytes": max(len(r["text"].encode()) for r in records),
    }


def ai4p_values(r):
    for v, t in zip(r["pii_values"], r["pii_types"]):
        if t in AI4P_MAP:
            yield v, AI4P_MAP[t]


def synth_values(r):
    pay = r.get("pii_payload", {})
    for k, det in SYNTH_KEYS.items():
        v = pay.get(k)
        if v and v in r["text"]:
            yield v, det


if __name__ == "__main__":
    out = {
        "ai4privacy_500": evaluate(json.loads((ROOT / "eval/data/ai4privacy_500.json").read_text()), ai4p_values),
        "synth_500": evaluate(json.loads((ROOT / "eval/data/synth_500.json").read_text()), synth_values),
    }
    (ROOT / "eval/results").mkdir(exist_ok=True)
    (ROOT / "eval/results/detector_eval.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
