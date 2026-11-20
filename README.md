# Cancellation-Summation Merkle Tree (CSMT)

This repository holds the reference implementation and benchmarks of the cancellation-summation Merkle tree (CSMT), a zero-knowledge proof of liabilities for proof of reserves.

CSMT binds both legs of every trade in the snapshot buffer (delta) to a public ledger through zero-sum accumulators and role-separated grand product checks. This mitigates snapshot cherry-picking without halting the trading engine.

## 1. Repository structure

```
csmt-repo/
├── circuit/
│   ├── circuit.go      # R1CS batch circuit (ProveBatch, Algorithm 4) for Groth16 in gnark
│   ├── config.go       # Scenario parameters and the benchmark trades
│   └── witness.go      # Native witness generator (Poseidon commitments, roots, aggregates)
├── verifier/
│   └── verifier.go     # Client inclusion check (Algorithm 3) and universal ledger audit (Algorithm 5)
├── cmd/
│   └── bench/
│       └── main.go     # Command-line driver that runs the scenarios and prints the results
├── scripts/
│   └── run_bench.sh    # Runs every scenario with its own log and peak memory
├── go.mod              # Go module definition
├── go.sum              # Dependency checksums
└── README.md           # This file
```

## 2. Requirements

* Go 1.21 or later. `go build` fetches the dependencies.
* Linux (Ubuntu 20.04 or 22.04 LTS recommended) or macOS.
* Prover: at least 64 GB of RAM for batch size N = 512.
* Verifier: ordinary consumer hardware with 8 GB of RAM. Client verification uses one CPU core, and the universal audit uses every core (1.7 GB peak memory on a 32-thread server).
* Recommended: `numactl` on multi-socket (NUMA) servers, and GNU `time` (`/usr/bin/time -v`) to record peak memory.

## 3. Build

```bash
cd csmt-repo
go build -o bin/bench ./cmd/bench
```

## 4. Reproducing the results

### 4.1 All scenarios

```bash
./scripts/run_bench.sh
```

The script runs each scenario in its own process under `numactl --interleave=all` (when available) and GNU `time -v`. It writes `logs/<scenario>.log` and collects the result lines and each scenario's peak memory in `logs/summary.txt`. Set `BATCH_SIZE` and `ITERATIONS` in the environment to override the defaults.

### 4.2 One scenario

```bash
# 1. Baseline zk-SMT (no trades, K = 0)
./bin/bench -scenario baseline -batch-size 512 -iterations 10

# 2. CSMT at the extreme peak load (historical peak trade density, K = 10)
./bin/bench -scenario peak -batch-size 512 -iterations 10

# 3. CSMT under stress (one trade per ten batch users, K = 51)
./bin/bench -scenario stress -batch-size 512 -iterations 10

# 4. Verification (client inclusion check and universal public ledger audit)
./bin/bench -scenario verify
```

### 4.3 Multi-socket servers (NUMA)

On a dual-CPU server, interleave memory across both sockets and record the peak memory of each scenario:

```bash
numactl --hardware                       # confirm the two NUMA nodes
numactl --interleave=all /usr/bin/time -v ./bin/bench -scenario peak -batch-size 512 -iterations 10
```

## 5. Parameters

| Parameter | Notation | Default | Description |
| :--- | :---: | :---: | :--- |
| Global tree depth | `D` | `28` | Full Merkle tree with 2^28 ≈ 268.4 million accounts |
| Asset types | `M` | `256` | Each asset has an equity and a debt value, so each user has 512 64-bit bounds |
| Batch size | `N` | `512` | User accounts per batch subtree (2^9) |
| Subtree count | `B` | `524,288` | Number of batch subtrees (B = 2^(28-9) = 2^19) |
| Peak trades | `K_peak` | `10` | Historical peak density: 5.47 × 10^6 trades spread over B subtrees |
| Stress trades | `K_stress` | `51` | One trade per ten batch users. The 51 trades involve 102 distinct users. |
| Iterations | `n` | `10` | Proving runs per scenario, for the mean and standard deviation |

## 6. Circuit and workload notes

Each user leaf runs Algorithm 4 over its own trace slots (`u_i.trace`). For every leg, the circuit recomputes `h_calc` from the raw trade fields, asserts `h_calc == tx.hash`, extends the trace commitment `tau = Hash(tau, h_calc)`, and applies the bidder, asker, or FAIL branch to the accumulator and the role-separated grand products. The leaf ID is the global leaf position `BatchIndex * N + i`, computed in-circuit. The leaf hash binds `(ID, assets, Acc, tau)` before the challenge `gamma = Hash(Root_U, Root_T)` is used. Here `assets` is the sponge commitment to every equity and debt value.

Trace capacities are fixed per leaf at compile time and sum to the 2K legs of the batch. The trace consistency track therefore costs a constant number of constraints per trade, whatever N is and however the trades are spread across users, so the circuit scales as O(N + K). Unused slots are padded with `Active = 0`.

Batches are chained as in Binance's deployed zk-PoR (`github.com/binance/zkmerkle-proof-of-solvency`). Each batch proof authenticates its sub-root under the shared `Root_U` at `BatchIndex` and moves a commitment to the running aggregate from `AggBefore` to `AggAfter`. The aggregate holds the equity and debt totals of each asset, `Acc`, `Pi+`, and `Pi-`. A verifier checks each batch proof, the shared roots, the chain `AggAfter_b == AggBefore_{b+1}`, and that the batch indices are contiguous. It then opens the final aggregate and checks `Acc == 0` and `Pi+ == Pi- == Pi_public != 0`. Per-batch sums stay hidden behind the commitments.

The witness generator assigns synthetic balances and trades and computes every commitment natively with the same Poseidon hash, so each generated proof verifies. The constraint count depends only on the circuit shape.

## 7. Reading the output

* `Total Const` and `Const/User`: the total R1CS constraint count, and that count divided by N (rounded down).
* `Proof Time`: mean ± standard deviation over the iterations. The standard deviation divides by n, not n - 1.
* `Verify`: Groth16 verification time of one batch proof. Multiplied by B, it is the time to check all chained batch proofs one after another.
* Client verification: single-core time of Algorithm 3 (receipt hashes, trace commitment, asset sponge, leaf hash, and the depth-28 path).
* Universal audit: multi-core time of Algorithm 5 over the public ledger, which recomputes `Root_T` and the grand product `Pi_public`.
* `Maximum resident set size`: the peak memory of each scenario, reported by GNU `time -v`.