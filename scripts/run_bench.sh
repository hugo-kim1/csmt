#!/usr/bin/env bash
# Runs every CSMT benchmark scenario in its own process, so that peak memory is reported per
# scenario, and writes logs/<scenario>.log and logs/summary.txt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

BATCH_SIZE="${BATCH_SIZE:-512}"
ITERATIONS="${ITERATIONS:-10}"

echo "[*] Building CSMT Benchmark Suite..."
go build -o bin/bench ./cmd/bench
mkdir -p logs

# Interleave memory across the sockets of a multi-CPU (NUMA) server
NUMA_CMD=""
if command -v numactl &> /dev/null; then
    NUMA_CMD="numactl --interleave=all"
    echo "[*] NUMA interleaving enabled: ${NUMA_CMD}"
fi

# GNU time reports the peak memory of each scenario ("Maximum resident set size")
TIME_CMD=""
if /usr/bin/time -v true &> /dev/null; then
    TIME_CMD="/usr/bin/time -v"
fi

for SCENARIO in baseline peak stress verify; do
    echo ""
    echo "=============================================================================="
    echo "Scenario: ${SCENARIO} (Batch Size N=${BATCH_SIZE}, ${ITERATIONS} Iterations)"
    echo "=============================================================================="
    ${NUMA_CMD} ${TIME_CMD} ./bin/bench -batch-size "${BATCH_SIZE}" -iterations "${ITERATIONS}" \
        -scenario "${SCENARIO}" 2>&1 | tee "logs/${SCENARIO}.log"
done

grep -H -e ">>> RESULT" -e "Batch proof verified" -e "Verification Latency" -e "Root_T Recomputation" \
    -e "Grand Product" -e "Total:" -e "Maximum resident set size" logs/*.log | tee logs/summary.txt

echo ""
echo "Benchmark suite completed. Summary: logs/summary.txt"
