from __future__ import annotations

import csv
import time
import statistics
import uuid
from pathlib import Path

from qkd_hake.crypto.kem import OQSKEM
from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeResult
from qkd_hake.qkd_mock.pool import QKDKeyPool, PoolExhausted


class SimulatedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.current_time = start

    def __call__(self) -> float:
        return self.current_time

    def advance(self, dt: float) -> None:
        self.current_time += dt


def run_performance_benchmarks(
    runs: int = 1000,
    output_dir: str = "results",
    warmup_runs: int = 100,
) -> None:
    """Compare hybrid and pure-PQC handshakes using paired measurements.

    Each recorded run executes HYBRID and PURE_PQC back-to-back for the same
    algorithm and key material. Warm-up runs are performed first and are not
    written to the raw CSV. Long-term KEM public keys are assumed to be
    provisioned before the handshake and therefore contribute zero bytes to
    per-handshake wire traffic.
    """
    if runs <= 0:
        raise ValueError("runs must be positive")
    if warmup_runs < 0:
        raise ValueError("warmup_runs must be non-negative")

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    algorithms = [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "FrodoKEM-976-AES",
    ]

    print(
        f"Starting paired benchmark suite: {runs} recorded runs + "
        f"{warmup_runs} warm-up runs per algorithm..."
    )

    csv_file = out_path / "performance_benchmarks.csv"

    with csv_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow([
            "algorithm",
            "mode",
            "pair_run",
            "latency_ms",
            "cpu_time_ms",
            "bytes_on_wire",
            "qkd_key_id_bytes",
            "long_term_public_keys_transmitted",
        ])

        for alg in algorithms:
            print(f"\nBenchmarking {alg}:")

            kem = OQSKEM(alg)
            kp_a = kem.generate_keypair()
            kp_b = kem.generate_keypair()

            # The actual KME creates UUID key IDs.
            # A UUID string is 36 ASCII bytes and is the only QKD-related
            # identifier transmitted per hybrid handshake.
            # The 256-bit QKD secret itself is not sent.
            qkd_key = b"q" * 32
            qkd_key_id = str(uuid.uuid4())

            def mock_qkd_client(action, key_id=None):
                if action == "status":
                    return {
                        "stored_key_count": 100,
                        "max_key_count": 128,
                    }

                if action == "get":
                    return qkd_key, qkd_key_id

                return qkd_key

            def run_handshake(mode: str) -> tuple[float, float, int, int]:
                t_wall_start = time.perf_counter_ns()
                t_cpu_start = time.process_time_ns()

                alice = AliceSession(
                    "alice",
                    kp_a.public_key,
                    kp_a.secret_key,
                    "bob",
                    kp_b.public_key,
                    alg,
                )

                bob = BobSession(
                    "alice",
                    kp_a.public_key,
                    "bob",
                    kp_b.public_key,
                    kp_b.secret_key,
                    alg,
                )

                ct1, nonce_a = alice.message1()

                pk_e, tau1, ct2, nonce_b = bob.message2(
                    (ct1, nonce_a)
                )

                if mode == "HYBRID":
                    ct_star, q_id, tau2 = alice.message3(
                        (pk_e, tau1, ct2, nonce_b),
                        qkd_pool_client_fn=mock_qkd_client,
                        allow_explicit_fallback=False,
                    )
                else:
                    ct_star, q_id, tau2 = alice.message3(
                        (pk_e, tau1, ct2, nonce_b),
                        qkd_pool_client_fn=None,
                        allow_explicit_fallback=True,
                    )

                tau3, bob_res = bob.message4(
                    (ct_star, q_id, tau2),
                    qkd_pool_client_fn=(
                        (lambda kid: qkd_key)
                        if mode == "HYBRID"
                        else None
                    ),
                )

                alice_res = alice.derive_and_verify(tau3)

                if alice_res.session_key != bob_res.session_key:
                    raise RuntimeError(
                        "paired benchmark handshake derived different keys"
                    )

                t_wall_end = time.perf_counter_ns()
                t_cpu_end = time.process_time_ns()

                lat_ms = (
                    t_wall_end - t_wall_start
                ) / 1_000_000.0

                cpu_ms = (
                    t_cpu_end - t_cpu_start
                ) / 1_000_000.0

                qid_bytes = len(
                    q_id.encode("utf-8")
                )

                bytes_on_wire = (
                    len(ct1)
                    + len(nonce_a)
                    + len(pk_e)
                    + len(tau1)
                    + len(ct2)
                    + len(nonce_b)
                    + len(ct_star)
                    + qid_bytes
                    + len(tau2)
                    + len(tau3)
                )

                return (
                    lat_ms,
                    cpu_ms,
                    bytes_on_wire,
                    qid_bytes,
                )

            # Warm-up runs are excluded from reported statistics.
            for _ in range(warmup_runs):
                run_handshake("HYBRID")
                run_handshake("PURE_PQC")

            stats: dict[
                str,
                dict[str, list[float] | list[int]]
            ] = {
                "HYBRID": {
                    "lat": [],
                    "cpu": [],
                    "bytes": [],
                    "qid": [],
                },
                "PURE_PQC": {
                    "lat": [],
                    "cpu": [],
                    "bytes": [],
                    "qid": [],
                },
            }

            for pair_run in range(1, runs + 1):

                # Alternate order so one mode is not always measured first.
                if pair_run % 2:
                    pair_modes = (
                        "HYBRID",
                        "PURE_PQC",
                    )
                else:
                    pair_modes = (
                        "PURE_PQC",
                        "HYBRID",
                    )

                for mode in pair_modes:

                    (
                        lat_ms,
                        cpu_ms,
                        wire_bytes,
                        qid_bytes,
                    ) = run_handshake(mode)

                    stats[mode]["lat"].append(lat_ms)  # type: ignore[arg-type]
                    stats[mode]["cpu"].append(cpu_ms)  # type: ignore[arg-type]
                    stats[mode]["bytes"].append(wire_bytes)  # type: ignore[arg-type]
                    stats[mode]["qid"].append(qid_bytes)  # type: ignore[arg-type]

                    writer.writerow([
                        alg,
                        mode,
                        pair_run,
                        lat_ms,
                        cpu_ms,
                        wire_bytes,
                        qid_bytes,
                        0,
                    ])

            for mode in (
                "HYBRID",
                "PURE_PQC",
            ):
                latencies = stats[mode]["lat"]  # type: ignore[assignment]
                cpus = stats[mode]["cpu"]  # type: ignore[assignment]
                wire_sizes = stats[mode]["bytes"]  # type: ignore[assignment]

                med_lat = statistics.median(
                    latencies
                )

                p95_lat = np_percentile(
                    latencies,
                    95,
                )

                med_cpu = statistics.median(
                    cpus
                )

                p95_cpu = np_percentile(
                    cpus,
                    95,
                )

                print(
                    f"  [{mode}] "
                    f"Latency: Median={med_lat:.3f}ms, "
                    f"p95={p95_lat:.3f}ms | "
                    f"CPU Median={med_cpu:.3f}ms, "
                    f"p95={p95_cpu:.3f}ms | "
                    f"Bytes={wire_sizes[0]}"
                )


def np_percentile(
    data: list[float],
    percentile: float,
) -> float:
    """Calculate a deterministic linearly interpolated percentile."""

    if not data:
        return 0.0

    if not 0 <= percentile <= 100:
        raise ValueError(
            "percentile must be between 0 and 100"
        )

    ordered = sorted(data)

    if len(ordered) == 1:
        return ordered[0]

    position = (
        len(ordered) - 1
    ) * (
        percentile / 100.0
    )

    lower = int(position)

    upper = min(
        lower + 1,
        len(ordered) - 1,
    )

    fraction = position - lower

    return (
        ordered[lower]
        + (
            ordered[upper]
            - ordered[lower]
        ) * fraction
    )


def sweep_bottleneck_analysis(
    output_dir: str = "results",
    *,
    measurement_seconds: float = 60.0,
    repeats: int = 5,
    pool_depths: tuple[int, ...] = (16, 64, 128),
) -> None:
    """Measure temporary QKD burst capacity and steady-state capacity.

    The experiment has two separate phases.

    Phase 1 - Burst capacity:
        Start with a full QKD pool and measure the actual time until the
        first QKD request fails. This is compared against the theoretical
        depletion-time formula.

    Phase 2 - Steady state:
        Continue from the depleted state and measure QKD success over a
        fixed measurement window. This prevents the initial pool reserve
        from being confused with sustainable QKD throughput.

    For non-overloaded cases, there is no finite depletion time. A short
    warm-up is used before the steady-state measurement instead.
    """

    if measurement_seconds <= 0:
        raise ValueError(
            "measurement_seconds must be positive"
        )

    if repeats <= 0:
        raise ValueError(
            "repeats must be positive"
        )

    if (
        not pool_depths
        or any(depth <= 0 for depth in pool_depths)
    ):
        raise ValueError(
            "pool_depths must contain positive values"
        )

    out_path = Path(output_dir)
    out_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Offered handshake/request rates.
    handshake_rates = [
        1,
        5,
        10,
        20,
        50,
        100,
    ]

    # QKD supply rates.
    qkd_supply_rates = [
        1,
        10,
        100,
    ]

    key_size_bits = 256

    # Warm-up is only needed for cases where the QKD supply is
    # sufficient to keep up with demand.
    non_overloaded_warmup_seconds = 10.0

    print(
        "\nStarting corrected WP6 starvation sweep..."
    )

    print(
        f"Burst: measured actual depletion | "
        f"Steady-state measurement: "
        f"{measurement_seconds:.1f}s | "
        f"Repeats: {repeats} | "
        f"Pool depths: {list(pool_depths)}"
    )

    csv_file = (
        out_path
        / "bottleneck_steady_state.csv"
    )

    with csv_file.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "qkd_supply_rate_kbps",
            "qkd_key_size_bits",
            "pool_depth_keys",
            "initial_keys",
            "handshake_rate_req_s",
            "repeat",
            "sustainable_qkd_rate_req_s",
            "theoretical_burst_duration_s",
            "measured_burst_duration_s",
            "burst_measurement_status",
            "burst_error_pct",
            "steady_state_start_condition",
            "warmup_seconds_non_overloaded",
            "measurement_seconds",
            "measurement_attempts",
            "qkd_successes",
            "qkd_failures",
            "steady_state_qkd_success_rate_pct",
            "final_pool_occupancy_keys",
            "final_pool_occupancy_pct",
            "starved",
        ])

        for supply in qkd_supply_rates:

            # Convert kbps into bits/sec.
            refill_bps = supply * 1000

            # Convert QKD bit production into complete 256-bit
            # QKD keys per second.
            sustainable_rate = (
                refill_bps
                / key_size_bits
            )

            print(
                f"\nQKD supply: {supply} kbps "
                f"({sustainable_rate:.5f} keys/s)"
            )

            for rate in handshake_rates:

                for depth in pool_depths:

                    # A case is overloaded when requests arrive faster
                    # than QKD can produce complete keys.
                    overloaded = (
                        rate > sustainable_rate
                    )

                    # -------------------------------------------------
                    # THEORETICAL BURST DEPLETION TIME
                    # -------------------------------------------------
                    #
                    # If:
                    #
                    # initial pool = depth
                    # demand = rate
                    # QKD production = sustainable_rate
                    #
                    # then:
                    #
                    # net drain =
                    #     demand - QKD production
                    #
                    # and:
                    #
                    # burst duration =
                    #     initial pool / net drain
                    #
                    # This is only meaningful when demand exceeds
                    # sustainable QKD production.
                    # -------------------------------------------------

                    if overloaded:

                        theoretical_burst_duration = (
                            depth
                            / (
                                rate
                                - sustainable_rate
                            )
                        )

                    else:

                        theoretical_burst_duration = None

                    for repeat in range(
                        1,
                        repeats + 1,
                    ):

                        clock = SimulatedClock()

                        pool = QKDKeyPool(
                            refill_bps=refill_bps,
                            depth=depth,
                            initial_keys=depth,
                            key_size_bits=key_size_bits,
                            clock=clock,
                        )

                        # -------------------------------------------------
                        # PHASE 1:
                        # TEMPORARY BURST CAPACITY
                        # -------------------------------------------------
                        #
                        # Start with a completely full pool.
                        #
                        # We actually send requests until the first QKD
                        # request fails.
                        #
                        # Therefore measured_burst_duration is an actual
                        # experimental value, not just the theoretical
                        # calculation.
                        # -------------------------------------------------

                        measured_burst_duration = None
                        burst_status = (
                            "NOT_APPLICABLE"
                        )

                        if overloaded:

                            burst_start = clock()

                            # Safety limit so a coding/model problem cannot
                            # create an infinite loop.
                            max_burst_attempts = max(
                                depth * 4,
                                int(
                                    max(
                                        60.0,
                                        theoretical_burst_duration * 3.0,
                                    )
                                    * rate
                                ),
                            )

                            for _ in range(
                                max_burst_attempts
                            ):

                                clock.advance(
                                    1.0 / rate
                                )

                                try:

                                    pool.issue(
                                        "alice",
                                        "bob",
                                        1,
                                    )

                                except PoolExhausted:

                                    measured_burst_duration = (
                                        clock()
                                        - burst_start
                                    )

                                    burst_status = (
                                        "MEASURED"
                                    )

                                    break

                            if (
                                measured_burst_duration
                                is None
                            ):

                                raise RuntimeError(
                                    "Burst measurement did not "
                                    "observe QKD depletion within "
                                    "the safety limit"
                                )

                        # -------------------------------------------------
                        # PHASE 2:
                        # STEADY-STATE MEASUREMENT
                        # -------------------------------------------------
                        #
                        # OVERLOADED:
                        #   Start immediately after the first QKD failure.
                        #
                        # NON-OVERLOADED:
                        #   No depletion occurs, so use a 10-second warm-up.
                        # -------------------------------------------------

                        warmup_seconds = 0.0

                        if not overloaded:

                            warmup_seconds = (
                                non_overloaded_warmup_seconds
                            )

                            warmup_attempts = int(
                                rate
                                * warmup_seconds
                            )

                            for _ in range(
                                warmup_attempts
                            ):

                                clock.advance(
                                    1.0 / rate
                                )

                                try:

                                    pool.issue(
                                        "alice",
                                        "bob",
                                        1,
                                    )

                                except PoolExhausted:

                                    # This should not occur for a
                                    # non-overloaded configuration.
                                    pass

                        # Number of requests in the fixed
                        # steady-state measurement window.
                        measurement_attempts = max(
                            1,
                            int(
                                rate
                                * measurement_seconds
                            ),
                        )

                        qkd_successes = 0
                        qkd_failures = 0

                        measurement_start = clock()

                        for _ in range(
                            measurement_attempts
                        ):

                            clock.advance(
                                1.0 / rate
                            )

                            try:

                                pool.issue(
                                    "alice",
                                    "bob",
                                    1,
                                )

                                qkd_successes += 1

                            except PoolExhausted:

                                qkd_failures += 1

                        measurement_end = clock()

                        actual_measurement_seconds = (
                            measurement_end
                            - measurement_start
                        )

                        qkd_success_rate = (
                            qkd_successes
                            / measurement_attempts
                            * 100.0
                        )

                        # -------------------------------------------------
                        # FINAL POOL STATE
                        # -------------------------------------------------

                        status = pool.status()

                        final_occupancy_keys = (
                            status[
                                "stored_key_count"
                            ]
                        )

                        final_occupancy_pct = (
                            final_occupancy_keys
                            / depth
                            * 100.0
                        )

                        # -------------------------------------------------
                        # BURST ERROR
                        # -------------------------------------------------

                        if (
                            measured_burst_duration
                            is not None
                        ):

                            burst_error_pct = (
                                (
                                    measured_burst_duration
                                    - theoretical_burst_duration
                                )
                                / theoretical_burst_duration
                                * 100.0
                            )

                        else:

                            burst_error_pct = None

                        # A case is marked starved when at least one
                        # QKD request failed during the steady-state
                        # measurement.
                        starved = (
                            "YES"
                            if qkd_failures > 0
                            else "NO"
                        )

                        # -------------------------------------------------
                        # WRITE RAW CSV RESULT
                        # -------------------------------------------------

                        writer.writerow([
                            supply,
                            key_size_bits,
                            depth,
                            depth,
                            rate,
                            repeat,
                            f"{sustainable_rate:.8f}",
                            (
                                ""
                                if theoretical_burst_duration
                                is None
                                else f"{theoretical_burst_duration:.6f}"
                            ),
                            (
                                ""
                                if measured_burst_duration
                                is None
                                else f"{measured_burst_duration:.6f}"
                            ),
                            burst_status,
                            (
                                ""
                                if burst_error_pct
                                is None
                                else f"{burst_error_pct:.6f}"
                            ),
                            (
                                "AFTER_FIRST_QKD_FAILURE"
                                if overloaded
                                else "AFTER_10S_WARMUP"
                            ),
                            f"{warmup_seconds:.6f}",
                            f"{measurement_seconds:.6f}",
                            measurement_attempts,
                            qkd_successes,
                            qkd_failures,
                            f"{qkd_success_rate:.6f}",
                            final_occupancy_keys,
                            f"{final_occupancy_pct:.6f}",
                            starved,
                        ])

                        # -------------------------------------------------
                        # PRINT RESULT
                        # -------------------------------------------------

                        if (
                            measured_burst_duration
                            is not None
                        ):

                            burst_text = (
                                f"{measured_burst_duration:.2f}s "
                                f"(theory "
                                f"{theoretical_burst_duration:.2f}s)"
                            )

                        else:

                            burst_text = "N/A"

                        print(
                            f"  depth={depth:3d} | "
                            f"rate={rate:3d}/s | "
                            f"burst={burst_text} | "
                            f"steady-state QKD="
                            f"{qkd_success_rate:6.2f}% | "
                            f"failures={qkd_failures}"
                        )

    print(
        "\nCorrected starvation results written to: "
        f"{csv_file}"
    )

# from __future__ import annotations

# import csv
# import time
# import statistics
# from pathlib import Path
# from qkd_hake.crypto.kem import OQSKEM
# from qkd_hake.protocol.hake import AliceSession, BobSession, HandshakeResult
# from qkd_hake.qkd_mock.pool import QKDKeyPool, PoolExhausted


# class SimulatedClock:
#     def __init__(self, start: float = 0.0) -> None:
#         self.current_time = start

#     def __call__(self) -> float:
#         return self.current_time

#     def advance(self, dt: float) -> None:
#         self.current_time += dt


# def run_performance_benchmarks(runs: int = 1000, output_dir: str = "results") -> None:
#     """Run performance benchmarks comparing Hybrid QKD-PQC HAKE and Pure-PQC HAKE."""
#     out_path = Path(output_dir)
#     out_path.mkdir(parents=True, exist_ok=True)
    
#     algorithms = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "FrodoKEM-976-AES"]
#     modes = ["HYBRID", "PURE_PQC"]
    
#     print(f"Starting benchmark suite over {runs} runs...")
    
#     csv_file = out_path / "performance_benchmarks.csv"
#     with csv_file.open("w", newline="", encoding="utf-8") as f:
#         writer = csv.writer(f)
#         writer.writerow([
#             "algorithm", "mode", "run", "latency_ms", "cpu_time_ms", "bytes_on_wire"
#         ])
        
#         for alg in algorithms:
#             print(f"\nBenchmarking {alg}:")
#             # Generate static keys
#             kem = OQSKEM(alg)
#             kp_a = kem.generate_keypair()
#             kp_b = kem.generate_keypair()
            
#             for mode in modes:
#                 latencies = []
#                 cpus = []
#                 wire_sizes = []
                
#                 # Mock QKD pool client function
#                 qkd_key = b"q" * 32
#                 qkd_key_id = "mock-qkd-key-id-12345"
                
#                 def mock_qkd_client(action, key_id=None):
#                     if action == "status":
#                         return {"stored_key_count": 100, "max_key_count": 128}
#                     elif action == "get":
#                         return qkd_key, qkd_key_id
#                     else:  # retrieve by id
#                         return qkd_key
                
#                 for run in range(runs):
#                     # Start timing
#                     t_wall_start = time.perf_counter_ns()
#                     t_cpu_start = time.process_time_ns()
                    
#                     # 4-Message Handshake Execution
#                     alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
#                     bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)
                    
#                     # Msg 1
#                     ct1, nonce_a = alice.message1()
                    
#                     # Msg 2
#                     pk_e, tau1, ct2, nonce_b = bob.message2((ct1, nonce_a))
                    
#                     # Msg 3
#                     if mode == "HYBRID":
#                         ct_star, q_id, tau2 = alice.message3(
#                             (pk_e, tau1, ct2, nonce_b),
#                             qkd_pool_client_fn=mock_qkd_client,
#                             allow_explicit_fallback=False
#                         )
#                     else:
#                         ct_star, q_id, tau2 = alice.message3(
#                             (pk_e, tau1, ct2, nonce_b),
#                             qkd_pool_client_fn=None,  # Forces pure PQC
#                             allow_explicit_fallback=True
#                         )
                    
#                     # Msg 4 / Confirmation
#                     tau3, bob_res = bob.message4(
#                         (ct_star, q_id, tau2),
#                         qkd_pool_client_fn=None if mode == "PURE_PQC" else (lambda kid: qkd_key)
#                     )
                    
#                     alice_res = alice.derive_and_verify(tau3)
                    
#                     # End timing
#                     t_wall_end = time.perf_counter_ns()
#                     t_cpu_end = time.process_time_ns()
                    
#                     lat_ms = (t_wall_end - t_wall_start) / 1_000_000.0
#                     cpu_ms = (t_cpu_end - t_cpu_start) / 1_000_000.0
#                     bytes_on_wire = (
#                         len(ct1)
#                         + len(nonce_a)
#                         + len(pk_e)
#                         + len(tau1)
#                         + len(ct2)
#                         + len(nonce_b)
#                         + len(ct_star)
#                         + len(q_id.encode('utf-8'))
#                         + len(tau2)
#                         + len(tau3)
#                     )
                    
#                     latencies.append(lat_ms)
#                     cpus.append(cpu_ms)
#                     wire_sizes.append(bytes_on_wire)
                    
#                     writer.writerow([alg, mode, run, lat_ms, cpu_ms, bytes_on_wire])
                
#                 # Report statistics
#                 med_lat = statistics.median(latencies)
#                 p95_lat = np_percentile(latencies, 95)
#                 med_cpu = statistics.median(cpus)
#                 p95_cpu = np_percentile(cpus, 95)
                
#                 print(f"  [{mode}] Latency: Median={med_lat:.3f}ms, 95th={p95_lat:.3f}ms | Bytes={wire_sizes[0]}")


# def np_percentile(data: list[float], percentile: float) -> float:
#     """Calculate percentile value from list of data."""
#     if not data:
#         return 0.0
#     size = len(data)
#     sorted_data = sorted(data)
#     idx = max(0, int(percentile / 100.0 * size) - 1)
#     return sorted_data[idx]


# def sweep_bottleneck_analysis(output_dir: str = "results") -> None:
#     """Sweep Handshake Rates vs QKD Supply Rates to find the KMS starvation knee curve."""
#     out_path = Path(output_dir)
#     out_path.mkdir(parents=True, exist_ok=True)
    
#     handshake_rates = [1, 5, 10, 20, 50, 100]  # req/s
#     qkd_supply_rates = [1, 10, 100]  # kbps
#     key_size_bits = 256
#     sim_duration_sec = 10.0  # Simulate 10 seconds of traffic
    
#     print("\nStarting Bottleneck Sweep Analysis...")
    
#     csv_file = out_path / "bottleneck_sweep.csv"
#     with csv_file.open("w", newline="", encoding="utf-8") as f:
#         writer = csv.writer(f)
#         writer.writerow([
#             "handshake_rate_req_s", "qkd_supply_rate_kbps", "success_rate", "final_pool_occupancy_pct", "starved"
#         ])
        
#         for supply in qkd_supply_rates:
#             print(f"\nQKD Supply Rate: {supply} kbps")
#             for rate in handshake_rates:
#                 # 1 kbps = 1000 bps
#                 refill_bps = supply * 1000
#                 clock = SimulatedClock()
                
#                 # Standard mock pool
#                 pool = QKDKeyPool(
#                     refill_bps=refill_bps,
#                     depth=128,
#                     initial_keys=128,
#                     key_size_bits=key_size_bits,
#                     clock=clock
#                 )
                
#                 total_handshakes = int(rate * sim_duration_sec)
#                 successful_hybrid = 0
                
#                 time_step = 1.0 / rate
                
#                 for _ in range(total_handshakes):
#                     clock.advance(time_step)
#                     try:
#                         # Try to issue a key
#                         pool.issue("alice", "bob", 1)
#                         successful_hybrid += 1
#                     except PoolExhausted:
#                         pass
                
#                 success_rate = (successful_hybrid / total_handshakes) * 100.0
#                 status = pool.status()
#                 final_occ_pct = (status["stored_key_count"] / status["max_key_count"]) * 100.0
#                 starved = "YES" if success_rate < 95.0 else "NO"
                
#                 print(f"  Rate: {rate:3d} req/s | Success: {success_rate:5.1f}% | Final Occupancy: {final_occ_pct:5.1f}% | Starved: {starved}")
#                 writer.writerow([rate, supply, success_rate, final_occ_pct, starved])
