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

fig, (a, b) = plt.subplots(1, 2, figsize=(COL_W, 1.6), gridspec_kw={"width_ratios": [1, 1.15], "wspace": 0.75})
med = [r["prove_s"]["median"] for r in rows]
a.fill_between(N, [r["prove_s"]["q1"] for r in rows], [r["prove_s"]["q3"] for r in rows], color=BLUE, alpha=0.18, lw=0)
a.plot(N, med, color=BLUE, lw=1.6, marker="o", ms=3.5, label="Tier 1")
a.plot([256], [tee["prove_s"]], ls="none", marker="D", ms=4, mfc="white", mec=INK, mew=1, label="Tier 1+2")
a.set_xscale("log", base=2)
a.set_xticks(N, [str(n) for n in N])
a.set_ylim(0, 1.2)
a.set_xlabel("Response capacity $N$ (bytes)")
a.set_ylabel("Prove time (s)")
a.set_title("(a) Proving time", loc="left")
a.legend(frameon=False, loc="upper left", handlelength=1.4, borderaxespad=0.1)
grid(a)

bd = bench["breakdown_n256"]
names = [("card", "Card (Luhn)"), ("ipv4", "IPv4"), ("phone_us", "US phone"), ("date", "Date"),
         ("ssn", "SSN"), ("email", "E-mail")]
labels = ["Base"] + [n for _, n in names] + ["Tier 2 sig."]
vals = [bd["none"]] + [bd[k] - bd["none"] for k, _ in names] + [tee["gates"] - bd["all"]]
order = sorted(range(len(vals)), key=lambda i: vals[i])
ys = range(len(order))
b.barh(ys, [vals[i] / 1000 for i in order], color=[INK if labels[i].startswith("Tier 2") else BLUE for i in order],
       height=0.62)
b.set_yticks(list(ys), [labels[i] for i in order])
for y, i in zip(ys, order):
    b.text(vals[i] / 1000 + 3, y, f"{vals[i] / 1000:.1f}k", va="center", fontsize=6.5, color=MUTED)
b.set_xlim(0, 175)
b.set_xlabel("Gates added, $N$=256 (k)")
b.set_title("(b) Gates per component", loc="left")
grid(b, "x")
b.tick_params(axis="y", length=0)
fig.savefig(OUT / "cost.pdf")
plt.close(fig)

# ---------------------------------------------------------------- Fig: detection vs Presidio
det, pres = load("detector_eval.json"), load("presidio_eval.json")
types = [("ssn", "SSN"), ("email", "E-mail"), ("phone_us", "US phone"), ("ipv4", "IPv4"), ("date", "Date"),
         ("card", "Card")]
fig, axes = plt.subplots(1, 3, figsize=(PAGE_W, 1.85),
                         gridspec_kw={"width_ratios": [1, 1, 0.8], "wspace": 0.38})


def recall_panel(ax, ds, title):
    present = [(k, n) for k, n in types if k in det[ds]["per_type"]]
    y = list(range(len(present)))[::-1]
    h = 0.38
    z = [det[ds]["per_type"][k]["recall"] for k, _ in present]
    p = [pres[ds]["per_type"][k]["recall"] for k, _ in present]
    ax.barh([v + h / 2 for v in y], z, height=h, color=BLUE, label="ZKPriv (in circuit)")
    ax.barh([v - h / 2 for v in y], p, height=h, color=ORANGE, label="Presidio")
    for v, a_, b_ in zip(y, z, p):
        ax.text(a_ + 0.015, v + h / 2, f"{a_:.2f}", va="center", fontsize=6, color=MUTED)
        ax.text(b_ + 0.015, v - h / 2, f"{b_:.2f}", va="center", fontsize=6, color=MUTED)
    ax.set_yticks(y, [n for _, n in present])
    ax.set_xlim(0, 1.12)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xlabel("Per-value recall")
    ax.set_title(title, loc="left")
    ax.tick_params(axis="y", length=0)
    grid(ax, "x")


recall_panel(axes[0], "synth_500", "(a) Synthetic US records (500)")
recall_panel(axes[1], "ai4privacy_500", "(b) ai4privacy records (500)")
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.08), handlelength=1.2)

c = axes[2]
ds_names = [("synth_500", "Synthetic"), ("ai4privacy_500", "ai4privacy")]
x = range(len(ds_names))
w = 0.36
z = [100 * det[d]["false_refusal_rate_scrubbed"] for d, _ in ds_names]
p = [100 * pres[d]["false_refusal_rate_scrubbed"] for d, _ in ds_names]
c.bar([i - w / 2 for i in x], z, width=w, color=BLUE)
c.bar([i + w / 2 for i in x], p, width=w, color=ORANGE)
for i, (a_, b_) in enumerate(zip(z, p)):
    c.text(i - w / 2, a_ + 1, f"{a_:.1f}%", ha="center", fontsize=6.5, color=INK)
    c.text(i + w / 2, b_ + 1, f"{b_:.1f}%", ha="center", fontsize=6.5, color=INK)
c.set_xticks(list(x), [n for _, n in ds_names])
c.set_ylim(0, 42)
c.set_ylabel("Refused (%), lower is better")
c.set_title("(c) Refused after PII removed", loc="left")
grid(c)
c.tick_params(axis="x", length=0)
fig.savefig(OUT / "detection.pdf")
plt.close(fig)
print("wrote", sorted(p.name for p in OUT.glob("*.pdf")))
