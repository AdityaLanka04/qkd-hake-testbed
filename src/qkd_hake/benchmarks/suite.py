from __future__ import annotations

import csv
import time
import statistics
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


def run_performance_benchmarks(runs: int = 1000, output_dir: str = "results") -> None:
    """Run performance benchmarks comparing Hybrid QKD-PQC HAKE and Pure-PQC HAKE."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    algorithms = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "FrodoKEM-976-AES"]
    modes = ["HYBRID", "PURE_PQC"]
    
    print(f"Starting benchmark suite over {runs} runs...")
    
    csv_file = out_path / "performance_benchmarks.csv"
    with csv_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "algorithm", "mode", "run", "latency_ms", "cpu_time_ms", "bytes_on_wire"
        ])
        
        for alg in algorithms:
            print(f"\nBenchmarking {alg}:")
            # Generate static keys
            kem = OQSKEM(alg)
            kp_a = kem.generate_keypair()
            kp_b = kem.generate_keypair()
            
            for mode in modes:
                latencies = []
                cpus = []
                wire_sizes = []
                
                # Mock QKD pool client function
                qkd_key = b"q" * 32
                qkd_key_id = "mock-qkd-key-id-12345"
                
                def mock_qkd_client(action, key_id=None):
                    if action == "status":
                        return {"stored_key_count": 100, "max_key_count": 128}
                    elif action == "get":
                        return qkd_key, qkd_key_id
                    else:  # retrieve by id
                        return qkd_key
                
                for run in range(runs):
                    # Start timing
                    t_wall_start = time.perf_counter_ns()
                    t_cpu_start = time.process_time_ns()
                    
                    # 4-Message Handshake Execution
                    alice = AliceSession("alice", kp_a.public_key, kp_a.secret_key, "bob", kp_b.public_key, alg)
                    bob = BobSession("alice", kp_a.public_key, "bob", kp_b.public_key, kp_b.secret_key, alg)
                    
                    # Msg 1
                    ct1 = alice.message1()
                    
                    # Msg 2
                    pk_e, tau1, ct2 = bob.message2(ct1)
                    
                    # Msg 3
                    if mode == "HYBRID":
                        ct_star, q_id, tau2 = alice.message3(
                            (pk_e, tau1, ct2),
                            qkd_pool_client_fn=mock_qkd_client,
                            allow_explicit_fallback=False
                        )
                    else:
                        ct_star, q_id, tau2 = alice.message3(
                            (pk_e, tau1, ct2),
                            qkd_pool_client_fn=None,  # Forces pure PQC
                            allow_explicit_fallback=True
                        )
                    
                    # Msg 4 / Confirmation
                    tau3, bob_res = bob.message4(
                        (ct_star, q_id, tau2),
                        qkd_pool_client_fn=None if mode == "PURE_PQC" else (lambda kid: qkd_key)
                    )
                    
                    alice_res = alice.derive_and_verify(tau3)
                    
                    # End timing
                    t_wall_end = time.perf_counter_ns()
                    t_cpu_end = time.process_time_ns()
                    
                    lat_ms = (t_wall_end - t_wall_start) / 1_000_000.0
                    cpu_ms = (t_cpu_end - t_cpu_start) / 1_000_000.0
                    bytes_on_wire = len(ct1) + len(pk_e) + len(tau1) + len(ct2) + len(ct_star) + len(q_id.encode('utf-8')) + len(tau2) + len(tau3)
                    
                    latencies.append(lat_ms)
                    cpus.append(cpu_ms)
                    wire_sizes.append(bytes_on_wire)
                    
                    writer.writerow([alg, mode, run, lat_ms, cpu_ms, bytes_on_wire])
                
                # Report statistics
                med_lat = statistics.median(latencies)
                p95_lat = np_percentile(latencies, 95)
                med_cpu = statistics.median(cpus)
                p95_cpu = np_percentile(cpus, 95)
                
                print(f"  [{mode}] Latency: Median={med_lat:.3f}ms, 95th={p95_lat:.3f}ms | Bytes={wire_sizes[0]}")


def np_percentile(data: list[float], percentile: float) -> float:
    """Calculate percentile value from list of data."""
    if not data:
        return 0.0
    size = len(data)
    sorted_data = sorted(data)
    idx = max(0, int(percentile / 100.0 * size) - 1)
    return sorted_data[idx]


def sweep_bottleneck_analysis(output_dir: str = "results") -> None:
    """Sweep Handshake Rates vs QKD Supply Rates to find the KMS starvation knee curve."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    handshake_rates = [1, 5, 10, 20, 50, 100]  # req/s
    qkd_supply_rates = [1, 10, 100]  # kbps
    key_size_bits = 256
    sim_duration_sec = 10.0  # Simulate 10 seconds of traffic
    
    print("\nStarting Bottleneck Sweep Analysis...")
    
    csv_file = out_path / "bottleneck_sweep.csv"
    with csv_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "handshake_rate_req_s", "qkd_supply_rate_kbps", "success_rate", "final_pool_occupancy_pct", "starved"
        ])
        
        for supply in qkd_supply_rates:
            print(f"\nQKD Supply Rate: {supply} kbps")
            for rate in handshake_rates:
                # 1 kbps = 1000 bps
                refill_bps = supply * 1000
                clock = SimulatedClock()
                
                # Standard mock pool
                pool = QKDKeyPool(
                    refill_bps=refill_bps,
                    depth=128,
                    initial_keys=128,
                    key_size_bits=key_size_bits,
                    clock=clock
                )
                
                total_handshakes = int(rate * sim_duration_sec)
                successful_hybrid = 0
                
                time_step = 1.0 / rate
                
                for _ in range(total_handshakes):
                    clock.advance(time_step)
                    try:
                        # Try to issue a key
                        pool.issue("alice", "bob", 1)
                        successful_hybrid += 1
                    except PoolExhausted:
                        pass
                
                success_rate = (successful_hybrid / total_handshakes) * 100.0
                status = pool.status()
                final_occ_pct = (status["stored_key_count"] / status["max_key_count"]) * 100.0
                starved = "YES" if success_rate < 95.0 else "NO"
                
                print(f"  Rate: {rate:3d} req/s | Success: {success_rate:5.1f}% | Final Occupancy: {final_occ_pct:5.1f}% | Starved: {starved}")
                writer.writerow([rate, supply, success_rate, final_occ_pct, starved])
