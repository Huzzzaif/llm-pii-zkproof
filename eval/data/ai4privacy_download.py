"""
Download and cache a sample of ai4privacy/pii-masking-400k for ZKPriv evaluation.

Uses English-locale records only. Saves to datasets/ai4privacy/sample.json
with a normalised schema that eval_ai4privacy.py can consume.
"""

import json
import ast
from pathlib import Path
from datasets import load_dataset

OUT = Path(__file__).parent / "sample.json"
N_SAMPLES = 500
LOCALE = "en"


def normalise_privacy_mask(raw) -> list[dict]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw.replace("'", '"'))
        except Exception:
            try:
                return ast.literal_eval(raw)
            except Exception:
                return []
    return []


def main():
    print("Streaming ai4privacy/pii-masking-400k (English only) …")
    ds = load_dataset(
        "ai4privacy/pii-masking-400k",
        split="train",
        streaming=True,
    )

    records = []
    for row in ds:
        if row.get("language", "").lower() != "en":
            continue
        mask = normalise_privacy_mask(row.get("privacy_mask", []))
        if not mask:
            continue
        pii_values = [m["value"] for m in mask if m.get("value")]
        pii_types  = [m["label"] for m in mask if m.get("label")]
        records.append({
            "id":          row["uid"],
            "domain":      "ai4privacy",
            "text":        row["source_text"],
            "pii_present": True,
            "pii_values":  pii_values,
            "pii_types":   pii_types,
            "locale":      row.get("locale", ""),
        })
        if len(records) >= N_SAMPLES:
            break

    with open(OUT, "w") as f:
        json.dump(records, f, indent=2)
    print(f"Saved {len(records)} records → {OUT}")


if __name__ == "__main__":
    main()
