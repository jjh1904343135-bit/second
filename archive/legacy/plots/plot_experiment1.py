#!/usr/bin/env python3
"""Plot experiment 1 from recorded trials; never substitute expected results."""

import argparse
import json
import math
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter


ROOT = Path(__file__).resolve().parents[1]
ATTACKS = {
    "P1_OMISSION": "P1: Selective\nOmission",
    "P2_STALE_MEMORY": "P2: Stale Memory\nReplay",
    "P3_SAME_SOURCE_ECHO": "P3: Same-Source\nEcho",
}
SCHEMES = {
    "B0_SIGNATURE_ONLY": ("B0: Signature Only", "#949ea8", "//", False),
    "B1_MEMBERSHIP_ONLY": ("B1: Membership Only", "#4e79a7", "\\\\", False),
    "B2_COMPLETE_QUERY_UNCHECKED_LINEAGE": (
        "B2: Complete Query (No Lineage)", "#e18727", "..", False
    ),
    "RC_PEH_REAL": ("RC-PEH (Ours)", "#007a5e", "", True),
}


def observed_rows(data):
    """Recount authorizations and cross-check the experiment's summary rows."""
    if data.get("real_proofs") is not True:
        raise ValueError("Expected a real-proof experiment result")
    cases = data["cases"]
    recorded = {(row["attack"], row["scheme"]): row for row in data["rows"]}
    if len(recorded) != len(data["rows"]):
        raise ValueError("Duplicate summary rows")
    output = {}
    for attack in ATTACKS:
        attacks = [c for c in cases if c["type"] == attack and c["sample"] == "attack"]
        controls = [c for c in cases if c["type"] == attack and c["sample"] != "attack"]
        if not attacks or not controls:
            raise ValueError(f"Missing attack or control trials: {attack}")
        if not all(c["expected_allow"] is False for c in attacks):
            raise ValueError(f"Attack labels disagree with the reference result: {attack}")
        if not all(c["expected_allow"] is True for c in controls):
            raise ValueError(f"Control labels disagree with the reference result: {attack}")
        for scheme in SCHEMES:
            def allowed(case):
                result = case if scheme == "RC_PEH_REAL" else case["baseline"][scheme]
                value = result["action_authorized"]
                if not isinstance(value, bool):
                    raise ValueError("Missing or invalid action authorization")
                return value

            blocked = sum(not allowed(c) for c in attacks)
            rejected = sum(not allowed(c) for c in controls)
            row = {
                "blocked": blocked,
                "attacks": len(attacks),
                "false_positive": rejected,
                "controls": len(controls),
                "interception_rate_pct": 100 * blocked / len(attacks),
                "false_positive_rate_pct": 100 * rejected / len(controls),
            }
            expected = recorded[(attack, scheme)]
            for field, value in row.items():
                if not math.isclose(expected[field], value, rel_tol=1e-9, abs_tol=1e-9):
                    raise ValueError(f"Summary/trial mismatch: {attack}, {scheme}, {field}")
            output[(attack, scheme)] = row
    return output


def plot(rows, destination):
    # Pool control counts rather than averaging rates with unequal denominators.
    rates = []
    for scheme in SCHEMES:
        controls = [rows[(attack, scheme)] for attack in ATTACKS]
        fpr = 100 * sum(r["false_positive"] for r in controls) / sum(r["controls"] for r in controls)
        rates.append([r["interception_rate_pct"] for r in controls] + [fpr])
    rates = np.asarray(rates)

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "DejaVu Serif"],
        "font.size": 10,
        "axes.labelsize": 10.5,
        "xtick.labelsize": 9.5,
        "ytick.labelsize": 9.5,
        "legend.fontsize": 9.0,
        "axes.edgecolor": "black",
        "axes.linewidth": 0.8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "savefig.facecolor": "white",
    })
    fig, ax = plt.subplots(figsize=(7.6, 2.85), dpi=300)
    x = np.array([0.0, 1.25, 2.50, 3.95])
    offsets = (np.arange(len(SCHEMES)) - (len(SCHEMES) - 1) / 2) * 0.21
    ax.yaxis.grid(True, linestyle="--", linewidth=0.6, alpha=0.55, color="#b8c0c8", zorder=0)
    ax.set_axisbelow(True)
    ax.axvspan(3.22, 4.68, color="#f1f4f7", alpha=0.95, zorder=0)
    ax.axvline(3.22, color="#7f8c9a", linestyle="--", linewidth=0.9, zorder=2)

    for index, (label, color, hatch, ours) in enumerate(SCHEMES.values()):
        # Display-only zero stubs, as in the supplied design; labels use actual rates.
        heights = np.where(rates[index] == 0, 1.8, rates[index])
        ax.bar(x + offsets[index], heights, width=0.18, color=color,
               edgecolor="#1a202c", linewidth=1.05 if ours else 0.65,
               hatch=hatch, label=label, zorder=3)

    # Merge adjacent equal values from observed data, rather than assuming 0/100.
    for group in range(len(x)):
        start = 0
        while start < len(SCHEMES):
            end = start + 1
            value = rates[start, group]
            while end < len(SCHEMES) and math.isclose(rates[end, group], value, abs_tol=1e-9):
                end += 1
            only_ours = start == len(SCHEMES) - 1
            fpr = group == len(x) - 1
            label = f"{value:g}%" + (" FPR" if fpr else "")
            ax.text(
                x[group] + float(np.mean(offsets[start:end])),
                (1.8 if value == 0 else value) + (2.0 if value == 0 else 2.2),
                label, ha="center", va="bottom",
                fontsize=8.8 if only_ours and value > 0 else 8.5,
                fontweight="bold" if value > 0 or fpr else "normal",
                color="#00664e" if only_ours and value > 0 else
                      "#2d3748" if fpr else "#1a202c" if value > 0 else "#4a5568",
            )
            start = end

    ax.text(1.25, 114.5, "Attack Interception Rate (↑ Higher is better)",
            ha="center", va="center", fontsize=9.2, fontweight="bold", color="#1a202c")
    ax.text(3.95, 114.5, "False Alarm (↓ Lower is better)",
            ha="center", va="center", fontsize=9.0, fontweight="bold", color="#3b4654")
    ax.set_xlim(-0.62, 4.68)
    ax.set_ylim(0, 122)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.yaxis.set_major_formatter(PercentFormatter(100, decimals=0))
    ax.set_ylabel("Rate (%)")
    ax.set_xticks(x, list(ATTACKS.values()) + ["Legitimate Controls\n(False Positive Rate)"])
    ax.tick_params(axis="x", length=0, pad=6)
    ax.tick_params(axis="y", direction="out", length=3)
    for edge in ["top", "right"]:
        ax.spines[edge].set_visible(False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.48, 1.17), ncol=4, frameon=False,
              handlelength=1.4, handleheight=0.75, columnspacing=1.2, handletextpad=0.45)
    fig.tight_layout()
    destination.mkdir(parents=True, exist_ok=True)
    for extension in ("png", "pdf", "svg"):
        target = destination / f"experiment1.{extension}"
        fig.savefig(target, dpi=300, bbox_inches="tight")
        print(target)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "results/experiment1/validation.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "plots/output")
    args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    plot(observed_rows(data), args.output_dir)


if __name__ == "__main__":
    main()
