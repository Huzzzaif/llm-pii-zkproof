"""Unified, span-based comparison of ZKPriv with baselines (one protocol for all).

For each record every system returns character spans it would block. An
annotated PII value counts as caught if any flagged span overlaps one of its
occurrences (type-agnostic: privacy only asks whether the value is blocked).
Over-blocking: the same system on the record with every annotated value
replaced by "X"; a record is over-blocked if anything is still flagged.

Systems
  zkpriv_std     in-circuit detectors, standard policy (birth dates only); spans from the
                 reference regexes, which are decision-equivalent to the circuit (difftest.py)
  zkpriv_strict  in-circuit detectors, strict policy (every date)
  *_t2           + tier-2 enclave NER (Presidio PERSON/LOCATION/NRP/ID types, score >= 0.5)
  presidio       Presidio, all recognizers, default threshold
  presidio_rx    Presidio pattern recognizers only (no NER model)
  spacy_ner      spaCy en_core_web_sm entities PERSON/GPE/LOC/ORG/DATE
  llm            llama3.2:3b asked to list PII substrings (eval/llm_baseline.py, cached)

    ~/Repos/selencllm_edge/venv/bin/python eval/compare.py {dev|test}
"""
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "circuits" / "gen"))
sys.path.insert(0, str(ROOT / "tee-sim"))
from card_dfa import ALNUM, MAX_LEN, MIN_LEN, luhn_ok  # noqa: E402
from detectors import PATTERNS  # noqa: E402
import enclave  # noqa: E402

SETS = {"dev": ["ai4privacy_500", "synth_500"], "test": ["ai4privacy_test_500", "synth_test_500"]}
GROUP = {  # annotation label -> reporting group
    "SOCIALNUM": "SSN / tax ID", "TAXNUM": "SSN / tax ID", "ssn": "SSN / tax ID",
    "EMAIL": "E-mail", "email": "E-mail",
    "TELEPHONENUM": "Phone", "phone": "Phone",
    "CREDITCARDNUMBER": "Card", "cc": "Card",
    "DATEOFBIRTH": "Date of birth", "dob": "Date of birth",
    "ip": "IP address",
    "GIVENNAME": "Name", "SURNAME": "Name", "name": "Name",
    "CITY": "Place", "STREET": "Place",
    "IDCARDNUM": "Other ID", "DRIVERLICENSENUM": "Other ID", "ACCOUNTNUM": "Other ID", "passport": "Other ID",
    "acct": "Other ID", "mrn": "Other ID", "iban": "Other ID",
}
STRUCTURED = ["SSN / tax ID", "E-mail", "Phone", "Card", "Date of birth", "IP address"]
SEM_ENTS = {"PERSON", "LOCATION", "NRP", "US_PASSPORT", "US_DRIVER_LICENSE", "US_BANK_NUMBER", "IBAN_CODE",
            "MEDICAL_LICENSE", "US_ITIN", "UK_NHS"}
OVERLAP_RE = {k: re.compile("(?=(" + v + "))") for k, v in PATTERNS.items()}


# ------------------------------------------------------------------ systems
STANDARD = [k for k in PATTERNS if k not in ("date", "date_text")]  # birth dates only
STRICT = list(PATTERNS)                                              # every date


def spans_t1(text, dets=None):
    out = []
    for k, rx in OVERLAP_RE.items():
        if dets is not None and k not in dets:
            continue
        for m in rx.finditer(text):
            out.append((m.start(1), m.end(1)))
    out += card_spans(text)
    return out


def card_spans(text):
    b, out, i, n = text, [], 0, len(text)
    alnum = {chr(c) for c in ALNUM}
    while i < n:
        if not b[i].isdigit() or (i > 0 and b[i - 1] in alnum):
            i += 1
            continue
        j, digits = i, []
        while j < n:
            if b[j].isdigit():
                digits.append(b[j]); j += 1
            elif b[j] in " -" and j + 1 < n and b[j + 1].isdigit():
                j += 1
            else:
                break
        if (j >= n or b[j] not in alnum) and MIN_LEN <= len(digits) <= MAX_LEN and luhn_ok("".join(digits)):
            out.append((i, j))
        i = j if j > i else i + 1
    return out


def presidio_results(text, threshold):
    return enclave.analyzer().analyze(text=text, language="en", score_threshold=threshold)


_rx_only = None


def presidio_rx(text):
    global _rx_only
    if _rx_only is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        conf = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": enclave.SPACY_MODEL}]}
        _rx_only = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=conf).create_engine(),
                                  supported_languages=["en"])
        _rx_only.registry.remove_recognizer("SpacyRecognizer")
    return [(r.start, r.end) for r in _rx_only.analyze(text=text, language="en")]


def spacy_ner(text):
    nlp = enclave.analyzer().nlp_engine.nlp["en"]
    return [(e.start_char, e.end_char) for e in nlp(text).ents if e.label_ in {"PERSON", "GPE", "LOC", "ORG", "DATE"}]


LLM_CACHE = {}


def llm(text):
    found = LLM_CACHE.get(text)
    if found is None:
        return None
    out = []
    for v in found:
        v = v.strip()
        if len(v) < 2:
            continue
        for m in re.finditer(re.escape(v), text):
            out.append((m.start(), m.end()))
    return out


def sem_spans(t):
    return [(r.start, r.end) for r in presidio_results(t, 0.5) if r.entity_type in SEM_ENTS]


SYSTEMS = {
    "zkpriv_std": lambda t: spans_t1(t, STANDARD),
    "zkpriv_strict": lambda t: spans_t1(t, STRICT),
    "zkpriv_std_t2": lambda t: spans_t1(t, STANDARD) + sem_spans(t),
    "zkpriv_strict_t2": lambda t: spans_t1(t, STRICT) + sem_spans(t),
    "presidio": lambda t: [(r.start, r.end) for r in presidio_results(t, 0.0)],
    "presidio_rx": presidio_rx,
    "spacy_ner": spacy_ner,
    "llm": llm,
}


# ------------------------------------------------------------------ data
def values_of(r):
    if "pii_types" in r:
        return list(zip(r["pii_values"], r["pii_types"]))
    pay = r.get("pii_payload", {})
    return [(v, k) for k, v in pay.items() if v and v in r["text"]]


def scrub(text, values):
    for v in sorted(set(values), key=len, reverse=True):
        text = text.replace(v, "X")
    return text


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 3), round(c + h, 3))


def evaluate(name, fn, records):
    hit, tot = defaultdict(int), defaultdict(int)
    refused = over = n_pii = 0
    for r in records:
        text = r["text"]
        spans = fn(text)
        if spans is None:
            return None
        vals = values_of(r)
        for v, lab in vals:
            g = GROUP.get(lab)
            if g is None:
                continue
            occ = [(m.start(), m.end()) for m in re.finditer(re.escape(v), text)]
            caught = any(a < e and b > s for (s, e) in occ for (a, b) in spans)
            tot[g] += 1
            hit[g] += caught
        if any(GROUP.get(l) in STRUCTURED for _, l in vals):
            n_pii += 1
            refused += bool(spans)
        sc = fn(scrub(text, [v for v, _ in vals]))
        over += bool(sc)
    per = {g: {"recall": round(hit[g] / tot[g], 3), "hits": hit[g], "n": tot[g], "ci95": wilson(hit[g], tot[g])}
           for g in tot}
    sh = sum(hit[g] for g in STRUCTURED if g in tot)
    st = sum(tot[g] for g in STRUCTURED if g in tot)
    ah, at = sum(hit.values()), sum(tot.values())
    return {"per_group": per,
            "structured_recall": round(sh / st, 3), "structured_ci95": wilson(sh, st), "structured_n": st,
            "all_recall": round(ah / at, 3), "all_ci95": wilson(ah, at), "all_n": at,
            "refusal_with_structured_pii": round(refused / max(1, n_pii), 3),
            "over_blocking": round(over / len(records), 3), "over_blocking_ci95": wilson(over, len(records)),
            "records": len(records)}


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "dev"
    only = sys.argv[2].split(",") if len(sys.argv) > 2 else list(SYSTEMS)
    cache = ROOT / "eval/results" / f"llm_baseline_{split}.json"
    if cache.exists():
        LLM_CACHE.update(json.loads(cache.read_text()))
    out = {}
    for ds in SETS[split]:
        recs = json.loads((ROOT / "eval/data" / f"{ds}.json").read_text())
        out[ds] = {}
        for name in only:
            res = evaluate(name, SYSTEMS[name], recs)
            if res is None:
                print(f"  {ds:20s} {name:12s} skipped (no cached LLM output)")
                continue
            out[ds][name] = res
            print(f"  {ds:20s} {name:12s} structured {res['structured_recall']:.3f}  all {res['all_recall']:.3f}  "
                  f"over-blocking {res['over_blocking']:.3f}", flush=True)
    dst = ROOT / "eval/results" / f"compare_{split}.json"
    prev = json.loads(dst.read_text()) if dst.exists() else {}
    for ds, v in out.items():
        prev.setdefault(ds, {}).update(v)
    dst.write_text(json.dumps(prev, indent=2))
