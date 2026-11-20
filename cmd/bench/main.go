package main

import (
	"flag"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"csmt/circuit"
	"csmt/verifier"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// runScenario compiles, sets up, and proves one scenario, then times the verification of one batch proof.
func runScenario(cfg circuit.Config) {
	// Free the memory left by the previous scenario
	runtime.GC()
	debug.FreeOSMemory()

	batchDepth := int(math.Log2(float64(cfg.NumUsers)))
	globalLevels := cfg.GlobalDepth - batchDepth
	numSubtrees := 1 << globalLevels

	fmt.Printf("\n[*] Scenario: %-25s | Global Depth: %d | Subtrees (B): %s | Batch Users (N): %-4d | Txs (K): %d\n",
		cfg.Name, cfg.GlobalDepth, formatNumber(numSubtrees), cfg.NumUsers, cfg.NumTxs)

	circ := circuit.NewCircuit(cfg)

	// 1. Compile the circuit to R1CS
	startCompile := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circ, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Printf(" Compilation Error: %v\n", err)
		return
	}
	constraints := ccs.GetNbConstraints()
	fmt.Printf("    -> Compiled (%v) | Constraints: %d\n", time.Since(startCompile), constraints)

	// 2. Groth16 setup for the proving and verifying keys (single party, for benchmarking only)
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf(" Setup Error: %v\n", err)
		return
	}
	fmt.Printf("    -> Setup Done (%v)\n", time.Since(startSetup))

	// Free the setup's allocations
	runtime.GC()
	debug.FreeOSMemory()

	// 3. Build the private and public witness
	w, err := circuit.CreateWitness(cfg)
	if err != nil {
		fmt.Printf(" Witness Error: %v\n", err)
		return
	}

	// 4. Prove the batch NumIterations times
	var durations []time.Duration
	fmt.Printf("    -> Proving (%d iterations): ", cfg.NumIterations)

	var proof groth16.Proof
	for i := 0; i < cfg.NumIterations; i++ {
		startProve := time.Now()
		proof, err = groth16.Prove(ccs, pk, w)
		dur := time.Since(startProve)
		durations = append(durations, dur)
		if err != nil {
			fmt.Printf("[ERR: %v] ", err)
			return
		}
		fmt.Printf("%v ", dur)
	}
	fmt.Println()

	// 5. Verify one batch proof. A verifier checks each of the B chained batch proofs once.
	publicWitness, _ := w.Public()
	const verifyRuns = 100
	startVerify := time.Now()
	for i := 0; i < verifyRuns; i++ {
		if err := groth16.Verify(proof, vk, publicWitness); err != nil {
			fmt.Printf("    -> Verification FAILED: %v\n", err)
			return
		}
	}
	verifyAvg := time.Since(startVerify) / verifyRuns
	fmt.Printf("    -> Batch proof verified: %v per proof (x %s batches = %.1f min, verified sequentially)\n",
		verifyAvg, formatNumber(numSubtrees), verifyAvg.Minutes()*float64(numSubtrees))

	// Mean and standard deviation of the proof times (the standard deviation divides by n, not n-1)
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	avg := sum / time.Duration(len(durations))

	var variance float64
	for _, d := range durations {
		diff := float64(d - avg)
		variance += diff * diff
	}
	stdDev := math.Sqrt(variance / float64(len(durations)))

	perUser := constraints / cfg.NumUsers

	fmt.Printf("\n>>> RESULT | %-20s | Total Const: %-10d | Const/User: %-8d | Proof Time (%d-run Avg): %v ± %.2fms | Verify: %v\n",
		cfg.Name, constraints, perUser, len(durations), avg, stdDev/1e6, verifyAvg)
	fmt.Println(strings.Repeat("-", 100))

	runtime.GC()
	debug.FreeOSMemory()
}

func formatNumber(n int) string {
	in := fmt.Sprintf("%d", n)
	out := ""
	for i, c := range in {
		if (len(in)-i)%3 == 0 && i != 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func main() {
	scenarioFlag := flag.String("scenario", "all", "Scenario to evaluate: all, baseline (1), peak (2), stress (3), verify (4)")
	batchSizeFlag := flag.Int("batch-size", 512, "Number of user leaves per subtree (e.g., 256, 512, 1024)")
	iterFlag := flag.Int("iterations", 10, "Number of proof generation benchmark repetitions")
	flag.Parse()

	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("   Cancellation-Summation Merkle Tree (CSMT) Zero-Knowledge Benchmark Suite   ")
	fmt.Println(strings.Repeat("=", 100))

	batchN := *batchSizeFlag
	globalDepth := 28
	numAssets := 256
	iterations := *iterFlag

	// Trades per batch scale with the batch size. The depth-28 tree holds about 268M accounts, and
	// the extreme peak is about 5.47M trades in the 5 s buffer across 256 pairs.
	subtrees := 1 << (globalDepth - int(math.Log2(float64(batchN))))
	kPeak := int(math.Round(5475840.0 / float64(subtrees)))
	kStress := int(math.Round(float64(batchN) * 0.10)) // stress: one trade per ten batch users

	cfgBaseline := circuit.Config{
		Name:          "Baseline zk-SMT",
		IsCSMT:        false,
		NumUsers:      batchN,
		NumAssets:     numAssets,
		NumTxs:        0,
		GlobalDepth:   globalDepth,
		NumIterations: iterations,
	}

	cfgPeak := circuit.Config{
		Name:          "CSMT (Extreme Peak)",
		IsCSMT:        true,
		NumUsers:      batchN,
		NumAssets:     numAssets,
		NumTxs:        kPeak,
		GlobalDepth:   globalDepth,
		NumIterations: iterations,
	}

	cfgStress := circuit.Config{
		Name:          "CSMT (Stress)",
		IsCSMT:        true,
		NumUsers:      batchN,
		NumAssets:     numAssets,
		NumTxs:        kStress,
		GlobalDepth:   globalDepth,
		NumIterations: iterations,
	}

	switch strings.ToLower(*scenarioFlag) {
	case "baseline", "1":
		runScenario(cfgBaseline)
	case "peak", "2":
		runScenario(cfgPeak)
	case "stress", "3":
		runScenario(cfgStress)
	case "verify", "4":
		verifier.RunVerificationBenchmark(globalDepth, numAssets)
	case "all":
		runScenario(cfgBaseline)
		runScenario(cfgPeak)
		runScenario(cfgStress)
		verifier.RunVerificationBenchmark(globalDepth, numAssets)
	default:
		fmt.Printf("Unknown scenario '%s'. Available options: all, baseline, peak, stress, verify\n", *scenarioFlag)
	}
}
