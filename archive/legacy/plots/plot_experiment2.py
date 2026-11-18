#!/usr/bin/env python3
"""Experiment 2: plot measured module costs; never impose expected scaling."""
import argparse
import json
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter
import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def load_results(source):
    data = json.loads(source.read_text(encoding="utf-8"))
    rows = {}
    for p in data["points"]:
        trials = p["trials"]
        if len(trials) != data["repeats"] or not all(t["verified"] is True for t in trials):
            raise ValueError(f"Unverified or missing proof: {p['id']}")
        for metric in ("prove_ms", "verify_ms"):
            measured = sum(t[metric] for t in trials) / len(trials)
            if not math.isclose(measured, p[metric], rel_tol=1e-9):
                raise ValueError(f"Incorrect mean: {p['id']} {metric}")
        key = (p["module"], p["size"])
        if key in rows:
            raise ValueError(f"Duplicate point: {key}")
        rows[key] = p
    expected = {(module, n) for module in ("psi", "gamma_q", "gamma_p") for n in (4,8,16,32,64)}
    expected |= {(module, k) for module in ("lambda_sorted", "lambda_naive") for k in (8,16,32,64,128)}
    if set(rows) != expected:
        raise ValueError("Incomplete parameter sweep")
    return data, rows


def plot(source, destination):
    data, rows = load_results(source)
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
        "font.size": 9, "axes.labelsize": 9, "xtick.labelsize": 8,
        "ytick.labelsize": 8, "legend.fontsize": 8,
        "axes.linewidth": 0.8, "pdf.fonttype": 42, "ps.fonttype": 42,
        "svg.fonttype": "none", "savefig.facecolor": "white",
    })
    fig, axes = plt.subplots(1, 3, figsize=(11.6, 3.0), dpi=300)
    green, orange, blue = "#007a5e", "#e18727", "#4e79a7"
    ks, ns = [8,16,32,64,128], [4,8,16,32,64]
    ax = axes[0]
    for module, label, color, marker in (
        ("lambda_sorted", "RC-PEH: sorted scan", green, "o"),
        ("lambda_naive", r"Naive: pairwise $O(K^2)$", orange, "s"),
    ):
        ax.plot(ks, [rows[module,k]["constraints"]/1000 for k in ks],
                label=label, color=color, marker=marker, markersize=4, linewidth=1.5)
    ax.set_xlabel(r"Dependency records $K$")
    ax.set_ylabel(r"Constraints ($\times 10^3$)")
    ax.set_xticks(ks)
    ax.set_title(r"(a) $\Lambda$: deduplication", fontsize=10, pad=9)
    ax.legend(frameon=False, loc="upper left", handlelength=1.7)

    ax = axes[1]
    for module, label, color, marker in (
        ("gamma_q", r"$\Gamma_Q$: query + $C_E$", blue, "s"),
        ("gamma_p", r"$\Gamma_P$: open $C_E$ + policy", green, "o"),
    ):
        values = [rows[module,n]["prove_ms"]/1000 for n in ns]
        errors = [np.std([t["prove_ms"]/1000 for t in rows[module,n]["trials"]], ddof=1) for n in ns]
        ax.errorbar(ns, values, yerr=errors, label=label, color=color,
                    marker=marker, markersize=4, linewidth=1.5, capsize=2)
    ax.set_xlabel(r"Policy records $|E_{\mathrm{policy}}|$")
    ax.set_ylabel("Prove time (s)")
    ax.set_xticks(ns)
    ax.set_title(r"(b) $\Gamma_Q$ vs. $\Gamma_P$", fontsize=10, pad=9)
    ax.legend(frameon=False, loc="upper left", handlelength=1.7)

    ax = axes[2]
    values = np.array([rows["psi",n]["prove_ms"]/1000 for n in ns])
    errors = [np.std([t["prove_ms"]/1000 for t in rows["psi",n]["trials"]], ddof=1) for n in ns]
    ax.errorbar(ns, values, yerr=errors, label="Measured batch update", color=green,
                marker="o", markersize=4, linewidth=1.5, capsize=2)
    coefficients = np.polyfit(ns, values, 1)
    fit = np.polyval(coefficients, ns)
    residual = float(np.sum((values-fit)**2))
    total = float(np.sum((values-np.mean(values))**2))
    r2 = 1-residual/total if total else None
    ax.plot(ns, fit, color="#949ea8", linestyle="--", linewidth=1,
            label=f"Linear fit ($R^2={r2:.3f}$)" if r2 is not None else "Linear fit")
    ax.set_xlabel(r"New log events $\Delta n$")
    ax.set_ylabel("Prove time (s)")
    ax.set_xticks(ns)
    ax.set_title(r"(c) $\Psi$: batch state update", fontsize=10, pad=9)
    ax.legend(frameon=False, loc="upper left", handlelength=1.7)
    for ax in axes:
        ax.yaxis.grid(True, linestyle="--", linewidth=0.6, alpha=0.55, color="#b8c0c8")
        ax.set_axisbelow(True)
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_ylim(bottom=0)
        ax.tick_params(direction="out", length=3)
        ax.yaxis.set_major_formatter(ScalarFormatter())
        ax.margins(x=0.06, y=0.1)
    fig.tight_layout(w_pad=1.8)
    destination.mkdir(parents=True, exist_ok=True)
    for extension in ("png", "pdf", "svg"):
        target = destination / f"experiment2.{extension}"
        fig.savefig(target, dpi=300, bbox_inches="tight")
        print(target)
    plt.close(fig)
    (destination/"experiment2_caption.md").write_text(
        f"Experiment 2. Real Circom/Groth16 component costs, depth {data['depth']}. "
        f"Each timing point averages {data['repeats']} randomized proofs of the same fixed witness; "
        "error bars show sample standard deviation, not population confidence intervals. "
        "(a) Total constraints including identical commitment/permutation-binding overhead; "
        "this measures the dedup kernel rather than full graph closure. "
        "(b) Query and policy share the actually verified C_E/context; no 10x speedup is assumed. "
        "(c) CREATE-only batch Merkle updates, not Nova IVC. All axes are linear. "
        f"Least-squares fit R²={r2:.4f}. "
        "All prove/verify times and raw repetitions are in results/experiment2/.\n",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT/"results/experiment2/validation.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT/"plots/output")
    args = parser.parse_args()
    plot(args.input, args.output_dir)


if __name__ == "__main__":
    main()
