"""Build the held-out TEST set (download: eval/data/raw/val_en.jsonl). Frozen before any detector tuning; the original
ai4privacy_500.json / synth_500.json become the DEVELOPMENT set.

ai4privacy: English records from the *validation* split (the dev set came from
the train split), shuffled with seed 2027, first 500 with at least one PII span.

    ~/Repos/selencllm_edge/venv/bin/python eval/data/make_heldout.py
"""
import ast
import json
import random
from pathlib import Path


OUT = Path(__file__).parent
SEED, N = 2027, 500


def mask_of(raw):
    if isinstance(raw, list):
        return raw
    try:
        return json.loads(raw.replace("'", '"'))
    except Exception:
        try:
            return ast.literal_eval(raw)
        except Exception:
            return []


def main():
    # data/validation/1en.jsonl from huggingface.co/datasets/ai4privacy/pii-masking-400k
    rows = (json.loads(l) for l in (OUT / "raw" / "val_en.jsonl").open())
    pool = []
    for row in rows:
        if row.get("language", "").lower() != "en":
            continue
        m = mask_of(row.get("privacy_mask", []))
        if not m:
            continue
        pool.append({"id": row["uid"], "domain": "ai4privacy", "text": row["source_text"],
                     "pii_present": True,
                     "pii_values": [x["value"] for x in m if x.get("value")],
                     "pii_types": [x["label"] for x in m if x.get("label")]})
    random.Random(SEED).shuffle(pool)
    test = pool[:N]
    (OUT / "ai4privacy_test_500.json").write_text(json.dumps(test, indent=1))
    print(f"ai4privacy test: {len(test)} records from a pool of {len(pool)} (validation split, seed {SEED})")


if __name__ == "__main__":
    main()
