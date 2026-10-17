"""LLM PII-detector baseline (the approach of SenseCLLM's detector agent and PromptObfus):
a local model lists every PII substring; results are cached for eval/compare.py.

Runs each record's original text and its scrubbed copy (for over-blocking).
    ollama serve &   then   python3 eval/llm_baseline.py {dev|test} [model]
"""
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETS = {"dev": ["ai4privacy_500", "synth_500"], "test": ["ai4privacy_test_500", "synth_test_500"]}
PROMPT = ("You are a PII detector. List every piece of personally identifiable information in the text below: "
          "names, addresses, cities, streets, phone numbers, e-mail addresses, dates of birth, SSNs, tax IDs, "
          "card numbers, account numbers, ID/passport/licence numbers, IP addresses, usernames and passwords.\n"
          "Return ONLY a JSON array of the exact substrings as they appear in the text, or [] if there are none.\n\n"
          "Text:\n{text}\n\nJSON array:")


def ask(model, text):
    body = json.dumps({"model": model, "prompt": PROMPT.format(text=text), "stream": False,
                       "options": {"temperature": 0, "seed": 42, "num_predict": 400}}).encode()
    req = urllib.request.Request("http://127.0.0.1:11434/api/generate", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        out = json.loads(r.read())["response"]
    m = re.search(r"\[.*\]", out, re.S)
    if not m:
        return []
    try:
        vals = json.loads(m.group(0))
    except json.JSONDecodeError:
        vals = re.findall(r'"([^"]+)"', m.group(0))
    return [str(v) for v in vals if isinstance(v, (str, int))]


def scrub(text, values):
    for v in sorted(set(values), key=len, reverse=True):
        text = text.replace(v, "X")
    return text


def values_of(r):
    if "pii_types" in r:
        return r["pii_values"]
    return [v for v in r.get("pii_payload", {}).values() if v and v in r["text"]]


if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "test"
    model = sys.argv[2] if len(sys.argv) > 2 else "llama3.2:3b"
    dst = ROOT / "eval/results" / f"llm_baseline_{split}.json"
    cache = json.loads(dst.read_text()) if dst.exists() else {}
    texts = []
    for ds in SETS[split]:
        for r in json.loads((ROOT / "eval/data" / f"{ds}.json").read_text()):
            texts += [r["text"], scrub(r["text"], values_of(r))]
    todo = [t for t in dict.fromkeys(texts) if t not in cache]
    t0 = time.time()
    for i, t in enumerate(todo):
        cache[t] = ask(model, t)
        if i % 50 == 0:
            dst.write_text(json.dumps(cache))
            print(f"{i}/{len(todo)}  {time.time() - t0:.0f}s", flush=True)
    dst.write_text(json.dumps(cache))
    print(f"done: {len(cache)} cached texts, model {model}")
