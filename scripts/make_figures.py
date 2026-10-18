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


# ---------------------------------------------------------------- Fig: cost
bench, tee = load("bench.json"), load("bench_tee.json")
rows = bench["scaling"]
N = [r["N"] for r in rows]

fig, (a, b) = plt.subplots(1, 2, figsize=(COL_W, 2.0), gridspec_kw={"width_ratios": [1, 1.15], "wspace": 0.85})
med = [r["prove_s"]["median"] for r in rows]
a.fill_between(N, [r["prove_s"]["q1"] for r in rows], [r["prove_s"]["q3"] for r in rows], color=BLUE, alpha=0.18, lw=0)
a.plot(N, med, color=BLUE, lw=1.6, marker="o", ms=3.5, label="Standard, 13 det.")
a.plot([256], [tee["prove_s"]], ls="none", marker="D", ms=4, mfc="white", mec=INK, mew=1, label="Standard + tier 2")
strict = load("bench_strict.json")
a.plot([256], [strict["prove_s"]], ls="none", marker="s", ms=4.5, color=AQ, label="Strict, 12 det.")
a.set_xscale("log", base=2)
a.set_xticks(N, [str(n) for n in N])
a.set_ylim(0, 4.5)
a.set_xlabel("Response capacity $N$ (bytes)")
a.set_ylabel("Prove time (s)")
a.set_title("(a) Proving time", loc="left")
a.annotate("standard (13 det.)", (64, med[0]), xytext=(-2, -13), textcoords="offset points", fontsize=6, ha="left", color=BLUE)
a.annotate("+ tier 2", (256, tee["prove_s"]), xytext=(-6, -2), textcoords="offset points", fontsize=6, color=INK, ha="right")
a.annotate("strict (12 det.)", (256, strict["prove_s"]), xytext=(6, -3), textcoords="offset points", fontsize=6, color=AQ)
grid(a)

bd = bench["breakdown_n256"]
names = [("dob", "Birth date"), ("card", "Card (Luhn)"), ("date_text", "Written date"),
         ("email_obf", "Obfusc. e-mail"), ("phone_intl", "Intl. phone"), ("phone_us", "US phone"),
         ("iban", "IBAN"), ("date", "Date"), ("ipv4", "IPv4"), ("id_prefixed", "Prefixed ID"),
         ("ssn", "SSN"), ("longnum", "Account no."), ("email", "E-mail")]
labels = ["Base"] + [n for _, n in names] + ["Tier 2 sig."]
vals = [bd["none"]] + [bd[k] - bd["none"] for k, _ in names] + [tee["gates"] - bd["all"]]
order = sorted(range(len(vals)), key=lambda i: vals[i])
ys = range(len(order))
b.barh(ys, [vals[i] / 1000 for i in order], color=[INK if labels[i].startswith("Tier 2") else BLUE for i in order],
       height=0.62)
b.set_yticks(list(ys), [labels[i] for i in order])
for y, i in zip(ys, order):
    b.text(vals[i] / 1000 + 3, y, f"{vals[i] / 1000:.1f}k", va="center", fontsize=6.5, color=MUTED)
b.set_xlim(0, 500)
b.set_xlabel("Gates added, $N$=256 (k)")
b.set_title("(b) Gates per component", loc="left")
grid(b, "x")
b.tick_params(axis="y", length=0)
fig.savefig(OUT / "cost.pdf")
plt.close(fig)

# ---------------------------------------------------------------- Fig: detection vs baselines (held-out test)
cmp = load("compare_test.json")
AQUA, YELLOW, MAGENTA = "#1baf7a", "#eda100", "#e87ba4"
SYS = [  # key, label, colour, marker, filled
    ("zkpriv_std", "ZKPriv std", BLUE, "o", True),
    ("zkpriv_strict", "ZKPriv strict", BLUE, "s", True),
    ("zkpriv_std_t2", "ZKPriv std+T2", BLUE, "o", False),
    ("zkpriv_strict_t2", "ZKPriv strict+T2", BLUE, "s", False),
    ("presidio", "Presidio", ORANGE, "^", True),
    ("presidio_rx", "Presidio patterns", AQUA, "D", True),
    ("spacy_ner", "spaCy NER", YELLOW, "v", True),
    ("llm", "LLM (Llama 3.2)", MAGENTA, "*", True),
]
NUDGE = {"zkpriv_std": (4, -9), "zkpriv_strict": (4, 3), "zkpriv_std_t2": (4, -9), "zkpriv_strict_t2": (4, 3),
         "presidio": (-4, 4), "presidio_rx": (4, -9), "spacy_ner": (-4, 4), "llm": (4, 3)}


def scatter(ax, ds, metric, title):
    d = cmp[ds]
    for key, lab, col, mk, filled in SYS:
        if key not in d:
            continue
        x, y = 100 * d[key]["over_blocking"], d[key][metric]
        ax.plot([x], [y], ls="none", marker=mk, ms=6.5 if mk != "*" else 9, mfc=col if filled else "white",
                mec=col, mew=1.4, zorder=3, label=lab)
    ax.set_xlim(-5, 100)
    ax.set_title(title, loc="left")
    ax.text(0.97, 0.04, "better: up and left", transform=ax.transAxes, fontsize=6, color=MUTED, ha="right")
    grid(ax, "both")


fig, axes = plt.subplots(1, 3, figsize=(PAGE_W, 2.15), gridspec_kw={"wspace": 0.22})
scatter(axes[0], "ai4privacy_test_500", "structured_recall", "(a) Structured PII, ai4privacy")
scatter(axes[1], "synth_test_500", "structured_recall", "(b) Structured PII, synthetic US")
scatter(axes[2], "ai4privacy_test_500", "all_recall", "(c) All PII incl. names, places, ai4privacy")
axes[0].set_ylabel("Recall (held-out test)")
for ax in axes:
    ax.set_ylim(0.05, 1.04)
fig.supxlabel("Over-blocking: records still refused after all PII is removed (%)", fontsize=7.5, y=-0.06)
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, frameon=False, loc="upper center", ncol=8, bbox_to_anchor=(0.5, 1.1), handletextpad=0.3,
           columnspacing=1.1, fontsize=6.5)
fig.savefig(OUT / "detection.pdf")
plt.close(fig)
print("wrote", sorted(p.name for p in OUT.glob("*.pdf")))
