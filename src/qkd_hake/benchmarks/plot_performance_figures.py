"""
Generate report-quality performance figures for the HAKE benchmark.

Input:
    results/performance_benchmarks.csv

Outputs:
    results/wp6_handshake_latency_median_p95.png
    results/wp6_message_size_comparison.png

The figures are generated directly from the benchmark CSV.
No benchmark values are manually entered.
"""

from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# FILE LOCATIONS
# ============================================================

CSV_PATH = Path("results/performance_benchmarks.csv")
OUTPUT_DIR = Path("results")


# ============================================================
# MAIN FUNCTION
# ============================================================

def main():

    # ------------------------------------------------------------
    # Load benchmark CSV
    # ------------------------------------------------------------

    if not CSV_PATH.exists():
        raise FileNotFoundError(
            f"Could not find {CSV_PATH}. "
            "Make sure performance_benchmarks.csv is inside results/."
        )

    df = pd.read_csv(CSV_PATH)

    # ------------------------------------------------------------
    # Check that the required columns exist.
    # ------------------------------------------------------------

    required_columns = {
        "algorithm",
        "mode",
        "latency_ms",
        "bytes_on_wire",
    }

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"CSV is missing columns: {sorted(missing_columns)}"
        )

    # ------------------------------------------------------------
    # Keep the same KEM order used by the benchmark.
    # ------------------------------------------------------------

    algorithms = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "FrodoKEM-976-AES",
    ]

    df["mode"] = df["mode"].str.upper()

    df = df[
        df["algorithm"].isin(algorithms)
    ].copy()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # ============================================================
    # CALCULATE LATENCY STATISTICS
    # ============================================================

    latency = (
        df.groupby(
            ["algorithm", "mode"]
        )["latency_ms"]
        .agg(
            median="median",
            p95=lambda values: values.quantile(0.95)
        )
        .reset_index()
    )

    # ============================================================
    # CALCULATE MESSAGE SIZE
    # ============================================================

    message_size = (
        df.groupby(
            ["algorithm", "mode"]
        )["bytes_on_wire"]
        .median()
        .reset_index(name="bytes")
    )

    # ============================================================
    # PREPARE LATENCY DATA
    # ============================================================

    hybrid_latency = (
        latency[
            latency["mode"] == "HYBRID"
        ]
        .set_index("algorithm")
        .reindex(algorithms)
    )

    pure_latency = (
        latency[
            latency["mode"] == "PURE_PQC"
        ]
        .set_index("algorithm")
        .reindex(algorithms)
    )

    hybrid_median = hybrid_latency["median"].values
    pure_median = pure_latency["median"].values

    hybrid_p95 = hybrid_latency["p95"].values
    pure_p95 = pure_latency["p95"].values

    # ============================================================
    # FIGURE 1
    #
    # HANDSHAKE LATENCY
    #
    # All four KEMs are shown together.
    #
    # Left panel  = median
    # Right panel = p95
    #
    # Logarithmic y-axis is used because FrodoKEM has much
    # larger latency than the ML-KEM configurations.
    # ============================================================

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(15, 6)
    )

    width = 0.34

    x = list(range(len(algorithms)))

    # ============================================================
    # LEFT PANEL
    # MEDIAN HANDSHAKE LATENCY
    # ============================================================

    ax = axes[0]

    hybrid_bars = ax.bar(
        [i - width / 2 for i in x],
        hybrid_median,
        width,
        label="Hybrid"
    )

    pure_bars = ax.bar(
        [i + width / 2 for i in x],
        pure_median,
        width,
        label="Pure-PQC"
    )

    # Use logarithmic scale so all four KEMs remain visible.
    ax.set_yscale("log")

    ax.set_xticks(x)

    ax.set_xticklabels(
        algorithms,
        rotation=15,
        ha="right"
    )

    ax.set_ylabel(
        "Handshake latency (ms, log scale)"
    )

    ax.set_title(
        "Median handshake latency"
    )

    ax.grid(
        axis="y",
        alpha=0.25
    )

    # ------------------------------------------------------------
    # Add exact median values.
    #
    # For FrodoKEM, the two labels are shifted horizontally so
    # that 73.998 ms and 72.717 ms do not overlap.
    # ------------------------------------------------------------

    for index, (bar, value) in enumerate(
        zip(hybrid_bars, hybrid_median)
    ):

        if index == len(algorithms) - 1:
            horizontal_shift = -10
        else:
            horizontal_shift = 0

        ax.annotate(
            f"{value:.3f} ms",
            xy=(
                bar.get_x() + bar.get_width() / 2,
                value
            ),
            xytext=(
                horizontal_shift,
                7
            ),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8
        )

    for index, (bar, value) in enumerate(
        zip(pure_bars, pure_median)
    ):

        if index == len(algorithms) - 1:
            horizontal_shift = 10
        else:
            horizontal_shift = 0

        ax.annotate(
            f"{value:.3f} ms",
            xy=(
                bar.get_x() + bar.get_width() / 2,
                value
            ),
            xytext=(
                horizontal_shift,
                7
            ),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8
        )

    ax.legend(
        loc="upper left"
    )

    # ============================================================
    # RIGHT PANEL
    # p95 HANDSHAKE LATENCY
    # ============================================================

    ax = axes[1]

    hybrid_bars = ax.bar(
        [i - width / 2 for i in x],
        hybrid_p95,
        width,
        label="Hybrid"
    )

    pure_bars = ax.bar(
        [i + width / 2 for i in x],
        pure_p95,
        width,
        label="Pure-PQC"
    )

    ax.set_yscale("log")

    ax.set_xticks(x)

    ax.set_xticklabels(
        algorithms,
        rotation=15,
        ha="right"
    )

    ax.set_ylabel(
        "Handshake latency (ms, log scale)"
    )

    ax.set_title(
        "95th-percentile (p95) handshake latency"
    )

    ax.grid(
        axis="y",
        alpha=0.25
    )

    # ------------------------------------------------------------
    # Add exact p95 values.
    #
    # FrodoKEM labels are shifted horizontally so that
    # 146.090 ms and 145.288 ms do not overlap.
    # ------------------------------------------------------------

    for index, (bar, value) in enumerate(
        zip(hybrid_bars, hybrid_p95)
    ):

        if index == len(algorithms) - 1:
            horizontal_shift = -10
        else:
            horizontal_shift = 0

        ax.annotate(
            f"{value:.3f} ms",
            xy=(
                bar.get_x() + bar.get_width() / 2,
                value
            ),
            xytext=(
                horizontal_shift,
                7
            ),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8
        )

    for index, (bar, value) in enumerate(
        zip(pure_bars, pure_p95)
    ):

        if index == len(algorithms) - 1:
            horizontal_shift = 10
        else:
            horizontal_shift = 0

        ax.annotate(
            f"{value:.3f} ms",
            xy=(
                bar.get_x() + bar.get_width() / 2,
                value
            ),
            xytext=(
                horizontal_shift,
                7
            ),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8
        )

    ax.legend(
        loc="upper left"
    )

    # ============================================================
    # OVERALL LATENCY FIGURE
    # ============================================================

    fig.suptitle(
        "HAKE Handshake Latency: Hybrid vs Pure-PQC",
        fontsize=14
    )

    fig.text(
        0.5,
        0.01,
        "Bars show the measured latency statistic. "
        "Left: median. Right: 95th percentile (p95). "
        "The logarithmic scale allows all four KEMs to be compared.",
        ha="center",
        fontsize=9
    )

    fig.tight_layout(
        rect=[0, 0.05, 1, 0.94]
    )

    latency_path = (
        OUTPUT_DIR
        / "wp6_handshake_latency_median_p95.png"
    )

    fig.savefig(
        latency_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close(fig)

    # ============================================================
    # PREPARE MESSAGE-SIZE DATA
    # ============================================================

    hybrid_size = (
        message_size[
            message_size["mode"] == "HYBRID"
        ]
        .set_index("algorithm")
        .reindex(algorithms)
    )

    pure_size = (
        message_size[
            message_size["mode"] == "PURE_PQC"
        ]
        .set_index("algorithm")
        .reindex(algorithms)
    )

    hybrid_bytes = hybrid_size["bytes"].values
    pure_bytes = pure_size["bytes"].values

    # ============================================================
    # FIGURE 2
    #
    # MESSAGE SIZE
    #
    # Simple direct comparison:
    #
    # Hybrid vs Pure-PQC
    #
    # across all four KEMs.
    # ============================================================

    fig, ax = plt.subplots(
        figsize=(11, 6)
    )

    x = list(range(len(algorithms)))

    hybrid_bars = ax.bar(
        [i - width / 2 for i in x],
        hybrid_bytes,
        width,
        label="Hybrid"
    )

    pure_bars = ax.bar(
        [i + width / 2 for i in x],
        pure_bytes,
        width,
        label="Pure-PQC"
    )

    ax.set_xticks(x)

    ax.set_xticklabels(
        algorithms,
        rotation=15,
        ha="right"
    )

    ax.set_ylabel(
        "Serialized message size (bytes)"
    )

    ax.set_title(
        "HAKE Message Size: Hybrid vs Pure-PQC"
    )

    ax.grid(
        axis="y",
        alpha=0.25
    )

    # ------------------------------------------------------------
    # Add exact byte values above the bars.
    # ------------------------------------------------------------

    max_size = max(
        max(hybrid_bytes),
        max(pure_bytes)
    )

    for bar, value in zip(
        hybrid_bars,
        hybrid_bytes
    ):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + max_size * 0.012,
            f"{int(value):,}",
            ha="center",
            va="bottom",
            fontsize=8
        )

    for bar, value in zip(
        pure_bars,
        pure_bytes
    ):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + max_size * 0.012,
            f"{int(value):,}",
            ha="center",
            va="bottom",
            fontsize=8
        )

    ax.legend(
        loc="upper left"
    )

    # ------------------------------------------------------------
    # Explain the 36-byte difference directly on the figure.
    # ------------------------------------------------------------

    ax.text(
        0.5,
        0.96,
        "Hybrid adds 36 bytes for the transmitted QKD key identifier",
        transform=ax.transAxes,
        ha="center",
        va="top",
        fontsize=9
    )

    fig.text(
        0.5,
        0.01,
        "The Hybrid configuration is consistently 36 bytes larger "
        "because of the transmitted QKD key identifier.",
        ha="center",
        fontsize=9
    )

    fig.tight_layout(
        rect=[0, 0.04, 1, 0.94]
    )

    size_path = (
        OUTPUT_DIR
        / "wp6_message_size_comparison.png"
    )

    fig.savefig(
        size_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close(fig)

    # ============================================================
    # FINISHED
    # ============================================================

    print()
    print("Generated successfully:")
    print()
    print(f"1. {latency_path}")
    print(f"2. {size_path}")
    print()


if __name__ == "__main__":
    main()