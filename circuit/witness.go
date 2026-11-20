package circuit

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

var modulus = ecc.BN254.ScalarField()

// Hash computes the circuit's Poseidon hash outside the circuit (iden3 parameters, up to 16 inputs).
func Hash(in ...*big.Int) *big.Int {
	h, err := poseidon.Hash(in)
	if err != nil {
		panic(err)
	}
	return h
}

// Sponge is the native version of spongeHash. It absorbs 15 inputs per Poseidon call.
func Sponge(in []*big.Int) *big.Int {
	state := big.NewInt(0)
	for j := 0; j < len(in); j += 15 {
		state = Hash(append([]*big.Int{state}, in[j:min(j+15, len(in))]...)...)
	}
	return state
}

func num(x int) *big.Int { return big.NewInt(int64(x)) }

// fold is the native version of combine: products multiply and the other tracks add, mod p.
func fold(mul bool, a, b *big.Int) *big.Int {
	r := new(big.Int)
	if mul {
		r.Mul(a, b)
	} else {
		r.Add(a, b)
	}
	return r.Mod(r, modulus)
}

// CreateWitness builds a satisfying witness for a configuration. It assigns synthetic balances and
// the benchmark trades, then computes every commitment natively: the tx hashes, traces, leaves,
// Root_U, gamma, and the aggregates.
func CreateWitness(cfg Config) (witness.Witness, error) {
	c := NewCircuit(cfg)
	n, m := cfg.NumUsers, cfg.NumAssets
	trades := cfg.Trades()
	batchIndex := 1
	base := batchIndex * n // leaf i holds ID base+i, its global leaf position

	// Trade fields (salt, asker, bidder, pair, ask amount, bid amount) and tx.hash
	txs, txh := make([][]*big.Int, len(trades)), make([]*big.Int, len(trades))
	traces := make([][]int, n)
	for t, tr := range trades {
		txs[t] = []*big.Int{num(t + 100), num(base + tr.Asker), num(base + tr.Bidder), num(1), num(100), num(250)}
		txh[t] = Hash(txs[t]...)
		if cfg.IsCSMT {
			traces[tr.Bidder] = append(traces[tr.Bidder], t)
			traces[tr.Asker] = append(traces[tr.Asker], t)
		}
	}

	// The empty aggregate: zero for the per-asset totals and acc, one for the products (track > 2M)
	empty := make([]*big.Int, len(c.Agg))
	for t := range empty {
		empty[t] = num(0)
		if t > 2*m {
			empty[t] = num(1)
		}
	}

	// Leaves: balances, asset commitment, accumulator, and trace commitment. None of them depends on gamma.
	nodes, totals := make([]*big.Int, n), slices.Clone(empty)
	slot := 0
	for i := 0; i < n; i++ {
		id := num(base + i)
		assets := make([]*big.Int, 0, 2*m)
		for k := 0; k < m; k++ {
			eq, debt := num(10000+i+k), num(k)
			c.Equities[i*m+k], c.Debts[i*m+k] = eq, debt
			assets = append(assets, eq, debt)
		}
		for t, v := range assets {
			totals[t] = fold(false, totals[t], v)
		}
		if !cfg.IsCSMT {
			nodes[i] = Hash(id, Sponge(assets))
			continue
		}
		acc, tau := num(0), num(0)
		for _, t := range traces[i] {
			c.Trace[slot] = Leg{txs[t][0], txs[t][1], txs[t][2], txs[t][3], txs[t][4], txs[t][5], txh[t], 1}
			slot++
			tau = Hash(tau, txh[t])
			if trades[t].Bidder == i {
				acc = fold(false, acc, txh[t])
			} else {
				acc = fold(false, acc, new(big.Int).Sub(modulus, txh[t]))
			}
		}
		totals[2*m] = fold(false, totals[2*m], acc)
		nodes[i] = Hash(id, Sponge(assets), acc, tau)
	}

	// Batch sub-root and its authentication path to Root_U at position BatchIndex
	for width := n / 2; width >= 1; width /= 2 {
		for j := 0; j < width; j++ {
			nodes[j] = Hash(nodes[2*j], nodes[2*j+1])
		}
	}
	rootT, root := num(888888), nodes[0] // stand-in Root_T: the circuit only hashes it into gamma, and Algorithm 5 checks it
	for l := range c.Siblings {
		c.Siblings[l] = num(l + 1)
		if (batchIndex>>l)&1 == 1 {
			root = Hash(num(l+1), root)
		} else {
			root = Hash(root, num(l+1))
		}
	}
	c.RootU, c.RootT, c.BatchIndex = root, rootT, batchIndex

	// Role-separated grand products over the batch legs, after gamma = Hash(Root_U, Root_T)
	gamma := Hash(root, rootT)
	for i := 0; i < n; i++ {
		for _, t := range traces[i] {
			if trades[t].Bidder == i {
				totals[2*m+1] = fold(true, totals[2*m+1], fold(false, txh[t], gamma))
			} else {
				totals[2*m+2] = fold(true, totals[2*m+2], fold(false, txh[t], gamma))
			}
		}
	}

	// The benchmark batch starts from the empty aggregate, as the first batch of a chain does
	after := make([]*big.Int, len(empty))
	for t := range empty {
		c.Agg[t], after[t] = empty[t], fold(t > 2*m, empty[t], totals[t])
	}
	c.AggBefore, c.AggAfter = Sponge(empty), Sponge(after)
	return frontend.NewWitness(c, ecc.BN254.ScalarField())
}
