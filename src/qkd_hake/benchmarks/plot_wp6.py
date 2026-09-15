"""
WP6 Figure Generation

Reads:
    results/bottleneck_steady_state.csv

and generates the three WP6 starvation figures.
"""

import csv
import os
from collections import defaultdict

import matplotlib.pyplot as plt


INPUT_FILE = "results/bottleneck_steady_state.csv"
OUTPUT_DIR = "results"


def read_results():
    """Read experiment results from the CSV file."""
    with open(INPUT_FILE, "r", newline="") as file:
        return list(csv.DictReader(file))


def generate_burst_capacity_figure(rows):
    """Figure 1: Burst duration versus initial pool depth."""

    data = defaultdict(list)

    for row in rows:
        if row["burst_measurement_status"] != "MEASURED":
            continue

        rate = float(row["handshake_rate_req_s"])
        depth = int(row["pool_depth_keys"])
        duration = float(row["measured_burst_duration_s"])

        data[(rate, depth)].append(duration)

    rates = sorted(set(rate for rate, _ in data.keys()))
    depths = sorted(set(depth for _, depth in data.keys()))

    plt.figure(figsize=(9, 6))

    for rate in rates:
        x_values = []
        y_values = []

        for depth in depths:
            values = data.get((rate, depth), [])

            if values:
                x_values.append(depth)
                y_values.append(sum(values) / len(values))

        if x_values:
            plt.plot(
                x_values,
                y_values,
                marker="o",
                linewidth=2,
                label=f"{rate:g} req/s",
            )

    plt.xlabel("Initial QKD Pool Depth (keys)")
    plt.ylabel("Measured Burst Duration (s)")
    plt.title("Temporary Burst Capacity vs. Initial QKD Pool Depth")
    plt.grid(True, alpha=0.3)
    plt.legend(title="Handshake Rate")
    plt.tight_layout()

    output_file = os.path.join(
        OUTPUT_DIR,
        "wp6_burst_capacity_vs_pool_depth.png",
    )

    plt.savefig(output_file, dpi=300)
    plt.close()

    print(f"Figure 1 generated: {output_file}")


def generate_steady_state_figure(rows):
    """Figure 2: Steady-state QKD success rate versus request rate."""

    data = defaultdict(list)

    for row in rows:
        rate = float(row["handshake_rate_req_s"])
        supply = float(row["qkd_supply_rate_kbps"])
        success_rate = float(row["steady_state_qkd_success_rate_pct"])

        data[(supply, rate)].append(success_rate)

    supplies = sorted(set(supply for supply, _ in data.keys()))
    rates = sorted(set(rate for _, rate in data.keys()))

    plt.figure(figsize=(9, 6))

    for supply in supplies:
        x_values = []
        y_values = []

        for rate in rates:
            values = data.get((supply, rate), [])

            if values:
                x_values.append(rate)
                y_values.append(sum(values) / len(values))

        if x_values:
            plt.plot(
                x_values,
                y_values,
                marker="o",
                linewidth=2,
                label=f"{supply:g} kbps QKD supply",
            )

    plt.xlabel("Handshake Request Rate (requests/s)")
    plt.ylabel("Steady-State QKD Success Rate (%)")
    plt.title("Steady-State QKD Success Rate vs. Handshake Rate")
    plt.ylim(0, 105)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()

    output_file = os.path.join(
        OUTPUT_DIR,
        "wp6_steady_state_qkd_success_rate.png",
    )

    plt.savefig(output_file, dpi=300)
    plt.close()

    print(f"Figure 2 generated: {output_file}")


def generate_measured_vs_theoretical_figure(rows):
    """
    Figure 3:
    Measured burst duration versus theoretical depletion time.

    Only overloaded cases are included.
    """

    data = defaultdict(list)

    for row in rows:
        if row["burst_measurement_status"] != "MEASURED":
            continue

        supply = float(row["qkd_supply_rate_kbps"])
        rate = float(row["handshake_rate_req_s"])

        theoretical = float(row["theoretical_burst_duration_s"])
        measured = float(row["measured_burst_duration_s"])

        data[(supply, rate)].append((theoretical, measured))

    supplies = sorted(set(supply for supply, _ in data.keys()))

    plt.figure(figsize=(9, 6))

    all_theoretical = []
    all_measured = []

    for supply in supplies:
        theoretical_values = []
        measured_values = []

        for (current_supply, rate), values in data.items():
            if current_supply != supply:
                continue

            for theoretical, measured in values:
                theoretical_values.append(theoretical)
                measured_values.append(measured)

                all_theoretical.append(theoretical)
                all_measured.append(measured)

        if theoretical_values:
            plt.scatter(
                theoretical_values,
                measured_values,
                s=45,
                label=f"{supply:g} kbps QKD supply",
            )

    if all_theoretical:
        minimum = min(all_theoretical + all_measured)
        maximum = max(all_theoretical + all_measured)

        plt.plot(
            [minimum, maximum],
            [minimum, maximum],
            linestyle="--",
            linewidth=1.5,
            label="Ideal: measured = theoretical",
        )

    plt.xlabel("Theoretical Burst Depletion Time (s)")
    plt.ylabel("Measured Burst Duration (s)")
    plt.title("Measured vs. Theoretical Burst Depletion Time")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()

    output_file = os.path.join(
        OUTPUT_DIR,
        "wp6_measured_vs_theoretical_burst.png",
    )

    plt.savefig(output_file, dpi=300)
    plt.close()

    print(f"Figure 3 generated: {output_file}")


def main():
    """Generate all WP6 figures from the experiment CSV."""

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: Could not find {INPUT_FILE}")
        print("Run the starvation experiment first:")
        print("python -m qkd_hake.cli sweep")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = read_results()

    print(f"Read {len(rows)} experiment rows from {INPUT_FILE}")

    generate_burst_capacity_figure(rows)
    generate_steady_state_figure(rows)
    generate_measured_vs_theoretical_figure(rows)

    print("All WP6 figures generated successfully.")


if __name__ == "__main__":
    main()