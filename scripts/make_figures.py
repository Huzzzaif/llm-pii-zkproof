"""Paper figures, drawn only from eval/results/*.json.

    ~/Repos/selencllm_edge/venv/bin/python scripts/make_figures.py  ->  paper/figs/*.pdf

Palette (validated for colour-vision deficiency): ZKPriv blue, Presidio orange.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "eval" / "results"
OUT = ROOT / "paper" / "figs"
OUT.mkdir(parents=True, exist_ok=True)

BLUE, ORANGE = "#2a78d6", "#eb6834"
AQ = "#1baf7a"
INK, MUTED, GRID = "#1f1f1e", "#6b6a64", "#e4e3de"
COL_W, PAGE_W = 3.5, 7.16  # IEEE column / page width, inches

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 7.5, "axes.titlesize": 7.5, "axes.labelsize": 7.5,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6,
    "pdf.fonttype": 42, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})


def load(name):
    return json.loads((R / name).read_text())


def grid(ax, axis="y"):
    ax.grid(axis=axis, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


# ---------------------------------------------------------------- Fig: R2 cost (line graph)
bench, tee = load("bench.json"), load("bench_tee.json")
ss = load("bench_strict_scaling.json")["scaling"]
std = bench["scaling"]
fig, ax = plt.subplots(figsize=(COL_W, 1.55))
for rows, col, lab in [(std, BLUE, "Standard policy (13 detectors)"), (ss, AQ, "Strict policy (12 detectors)")]:
    Ns = [r["N"] for r in rows]
    ax.fill_between(Ns, [r["prove_s"]["q1"] for r in rows], [r["prove_s"]["q3"] for r in rows], color=col, alpha=0.18, lw=0)
    ax.plot(Ns, [r["prove_s"]["median"] for r in rows], color=col, lw=1.8, marker="o", ms=3.5, label=lab)
    for r in rows:
        ax.annotate(f"{r['prove_s']['median']:.2f}", (r["N"], r["prove_s"]["median"]), xytext=(0, 4),
                    textcoords="offset points", ha="center", fontsize=6, color=INK)
ax.set_xscale("log", base=2)
ax.set_xticks([r["N"] for r in std], [str(r["N"]) for r in std])
ax.set_ylim(0, 4.6)
ax.set_xlabel("Response size $N$ (bytes)")
ax.set_ylabel("Prove time (s)")
ax.legend(frameon=False, loc="upper left", handlelength=1.5, fontsize=6.5)
grid(ax)
fig.savefig(OUT / "cost.pdf")
plt.close(fig)

# ---------------------------------------------------------------- Fig: R3 detection (horizontal bars)
cmp = load("compare_test.json")
SYSB = [("zkpriv_strict", "ZKPriv"), ("presidio", "Presidio"), ("presidio_rx", "Presidio patterns"),
        ("spacy_ner", "spaCy NER"), ("llm", "LLM detector")]
DS = [("ai4privacy_test_500", "ai4privacy", BLUE), ("synth_test_500", "Synthetic US", ORANGE)]
fig, axes = plt.subplots(1, 2, figsize=(COL_W, 1.9), sharey=True, gridspec_kw={"wspace": 0.12})
h = 0.38
ys = list(range(len(SYSB)))[::-1]
for ax, metric, scale, title, xmax, fmt in [(axes[0], "structured_recall", 1, "(a) Recall (higher is better)", 1.32, "{:.3f}"),
                                            (axes[1], "over_blocking", 100, "(b) Over-blocking % (lower is better)", 118, "{:.0f}")]:
    for k, (ds, dlab, col) in enumerate(DS):
        yy = [y + (0.5 - k) * h for y in ys]
        vals = [scale * cmp[ds][s][metric] for s, _ in SYSB]
        ax.barh(yy, vals, height=h * 0.9, color=col, label=dlab)
        for y, v in zip(yy, vals):
            ax.text(v + xmax * 0.015, y, fmt.format(v), va="center", fontsize=5.5, color=INK)
    ax.set_xlim(0, xmax)
    ax.set_title(title, loc="left", fontsize=6.8)
    ax.tick_params(axis="y", length=0)
    grid(ax, "x")
axes[0].set_xticks([0, 0.5, 1.0])
axes[1].set_xticks([0, 50, 100])
axes[0].set_yticks(ys, [n for _, n in SYSB], fontsize=6.5)
axes[0].get_yticklabels()[0].set_fontweight("bold")
hh, ll = axes[0].get_legend_handles_labels()
fig.legend(hh, ll, frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.58, 1.08), fontsize=6.5, handlelength=1.2)
fig.savefig(OUT / "detection.pdf")
plt.close(fig)
print("wrote", sorted(p.name for p in OUT.glob("*.pdf")))
