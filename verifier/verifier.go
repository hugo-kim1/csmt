package verifier

import (
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"time"

	"csmt/circuit"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BenchmarkClientVerification times the client-side check of Algorithm 3 with the circuit's
// Poseidon hash: each receipt hash, the trace commitment, the asset sponge, the leaf hash, and the
// Merkle path. It runs on a single thread, like a client on a phone or in a browser.
func BenchmarkClientVerification(globalDepth int, numAssets int, numLocalTxs int, iterations int) time.Duration {
	num := func(x int) *big.Int { return big.NewInt(int64(x)) }
	start := time.Now()
	for iter := 0; iter < iterations; iter++ {
		// 1. Receipt hashes h = Hash(salt, ask, bid, pair, amt_ask, amt_bid) and trace commitment tau = Hash(tau, h).
		// The Acc_local and Delta_net updates of Algorithm 3 are left out. They are a few additions per trade.
		tau := num(0)
		for t := 0; t < numLocalTxs; t++ {
			tau = circuit.Hash(tau, circuit.Hash(num(t+100), num(1), num(2), num(1), num(100), num(250)))
		}

		// 2. Sponge commitment to the equity and debt values of every asset
		assets := make([]*big.Int, 2*numAssets)
		for a := range assets {
			assets[a] = num(a)
		}

		// 3. Leaf hash Hash(ID, assets, Acc, tau) with stand-in ID and Acc values, and 4. the depth-D Merkle path
		node := circuit.Hash(num(12345), circuit.Sponge(assets), num(0), tau)
		for d := 0; d < globalDepth; d++ {
			node = circuit.Hash(node, num(d+1))
		}
	}
	return time.Since(start) / time.Duration(iterations)
}

// BenchmarkUniversalLedgerAudit times Algorithm 5 over the public trade ledger: it recomputes
// Root_T = MerkleRoot(T_public) and the grand product, both split across all cores.
func BenchmarkUniversalLedgerAudit(peakTxs int) (time.Duration, time.Duration, int) {
	numWorkers := 1
	for numWorkers*2 <= runtime.NumCPU() {
		numWorkers *= 2
	}
	size := numWorkers
	for size < peakTxs {
		size *= 2
	}

	// 1. Merkle root over T_public (zero-padded to a power of two), one subtree per worker. The ledger
	// holds the stand-in hashes 1, 2, 3, ..., which cost the same to hash as real ones.
	start := time.Now()
	roots := make([]*big.Int, numWorkers)
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			chunk := size / numWorkers
			level := make([]*big.Int, chunk)
			for j := range level {
				if idx := w*chunk + j; idx < peakTxs {
					level[j] = big.NewInt(int64(idx + 1))
				} else {
					level[j] = big.NewInt(0)
				}
			}
			for len(level) > 1 {
				for j := 0; j < len(level)/2; j++ {
					level[j] = circuit.Hash(level[2*j], level[2*j+1])
				}
				level = level[:len(level)/2]
			}
			roots[w] = level[0]
		}(w)
	}
	wg.Wait()
	for len(roots) > 1 {
		for j := 0; j < len(roots)/2; j++ {
			roots[j] = circuit.Hash(roots[2*j], roots[2*j+1])
		}
		roots = roots[:len(roots)/2]
	}
	merkleTime := time.Since(start)

	// 2. Grand product Pi_public = prod (h + gamma) over the same stand-in hashes
	txHashes := make([]fr.Element, peakTxs)
	for i := 0; i < peakTxs; i++ {
		txHashes[i].SetUint64(uint64(i + 1))
	}
	// Stand-in for gamma = Hash(Root_U, Root_T). One more hash would not change the timing.
	var gamma fr.Element
	gamma.SetString("12345678901234567890")

	chunkSize := (peakTxs + numWorkers - 1) / numWorkers
	start = time.Now()
	results := make([]fr.Element, numWorkers)
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var partialPi fr.Element
			partialPi.SetOne()
			for i := workerID * chunkSize; i < min((workerID+1)*chunkSize, peakTxs); i++ {
				var term fr.Element
				term.Add(&txHashes[i], &gamma)
				partialPi.Mul(&partialPi, &term)
			}
			results[workerID] = partialPi
		}(w)
	}
	wg.Wait()

	var finalPi fr.Element
	finalPi.SetOne()
	for w := 0; w < numWorkers; w++ {
		finalPi.Mul(&finalPi, &results[w])
	}
	// Algorithm 5 also asserts Pi_public != 0
	if finalPi.IsZero() {
		panic("invalid public grand product: Pi_pub cannot evaluate to zero")
	}
	return merkleTime, time.Since(start), numWorkers
}

// RunVerificationBenchmark runs and prints the client verification and universal ledger audit benchmarks.
func RunVerificationBenchmark(globalDepth int, numAssets int) {
	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("   CSMT Verification Benchmark (Client Inclusion Check and Universal Ledger Audit)   ")
	fmt.Println(strings.Repeat("=", 100))

	// 1. Client-side inclusion verification
	clientIterations := 1000
	numLocalTxs := 10
	avgClient := BenchmarkClientVerification(globalDepth, numAssets, numLocalTxs, clientIterations)
	proofPayloadBytes := globalDepth * 32

	fmt.Printf("\n[1. Client-Side User Inclusion Verification]\n")
	fmt.Printf("    -> Scope: Depth-%d Path + %d Assets Sponge + %d Local Txs Chaining\n", globalDepth, numAssets, numLocalTxs)
	fmt.Printf("    -> Proof Payload: %d bytes (%d hashes x 32 B)\n", proofPayloadBytes, globalDepth)
	fmt.Printf("    -> Verification Latency: %v (Single CPU Core)\n", avgClient)

	// 2. Universal public ledger audit (Algorithm 5)
	peakTxs := 5_470_000 // Extreme peak: 4,278 trades per second on each of 256 pairs for 5 s (5,475,840), rounded down to 5.47M
	merkleTime, productTime, numWorkers := BenchmarkUniversalLedgerAudit(peakTxs)
	ledgerSizeMB := float64(peakTxs*32) / (1024 * 1024)

	fmt.Printf("\n[2. Universal Public Ledger Audit]\n")
	fmt.Printf("    -> Target: Public Ledger with %s transactions\n", formatNumber(peakTxs))
	fmt.Printf("    -> Ledger Size: %.2f MB (%d txs x 32 B)\n", ledgerSizeMB, peakTxs)
	fmt.Printf("    -> Root_T Recomputation (%d workers): %v\n", numWorkers, merkleTime)
	fmt.Printf("    -> Grand Product (%d workers): %v (%.2f million txs/sec)\n",
		numWorkers, productTime, float64(peakTxs)/productTime.Seconds()/1e6)
	fmt.Printf("    -> Total: %v\n", merkleTime+productTime)
	fmt.Println(strings.Repeat("-", 100))
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
