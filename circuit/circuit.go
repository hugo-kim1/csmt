package circuit

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
)

// Leg is one entry of a user's trace (u_i.trace): the raw trade fields, the published hash
// tx.hash, and an Active flag. A slot with Active = 0 is padding.
type Leg struct {
	Salt, Asker, Bidder, Pair, AmtAsk, AmtBid, Hash, Active frontend.Variable
}

// TxCentricCircuit is the R1CS circuit for one CSMT batch (ProveBatch, Algorithm 4). Batches are
// chained through commitments to a running aggregate, as in Binance's deployed zk-PoR.
type TxCentricCircuit struct {
	Config Config

	// Private witness: the user balances. u_i.ID is not a witness. It is the leaf position BatchIndex*N + i.
	Equities []frontend.Variable // N x M asset equities
	Debts    []frontend.Variable // N x M asset debts

	// Trace slots of all users in leaf order. Config.TraceCaps gives each user's slot count.
	Trace []Leg

	// Running aggregate before this batch: the (eq, debt) totals of each asset, then acc, Pi+, Pi- for CSMT
	Agg []frontend.Variable

	// Merkle authentication path from the batch sub-root to Root_U
	Siblings []frontend.Variable

	// Public inputs
	RootU      frontend.Variable `gnark:",public"` // Global user state root
	RootT      frontend.Variable `gnark:",public"` // Root of the public trade ledger T_public
	BatchIndex frontend.Variable `gnark:",public"` // Position of the batch sub-root under Root_U
	AggBefore  frontend.Variable `gnark:",public"` // Commitment to the running aggregate before this batch
	AggAfter   frontend.Variable `gnark:",public"` // Commitment to the running aggregate after this batch
}

// NewCircuit allocates the slices of a circuit or witness for a configuration.
func NewCircuit(cfg Config) *TxCentricCircuit {
	n, m := cfg.NumUsers, cfg.NumAssets
	legs := 0
	for _, c := range cfg.TraceCaps() {
		legs += c
	}
	aggLen := 2 * m
	if cfg.IsCSMT {
		aggLen += 3
	}
	return &TxCentricCircuit{
		Config:   cfg,
		Equities: make([]frontend.Variable, n*m),
		Debts:    make([]frontend.Variable, n*m),
		Trace:    make([]Leg, legs),
		Agg:      make([]frontend.Variable, aggLen),
		Siblings: make([]frontend.Variable, cfg.GlobalDepth-(bits.Len(uint(n))-1)),
	}
}

// spongeHash absorbs a long input into one Poseidon state, 15 elements per call, which avoids a
// constraint blowup when a user holds many assets.
func spongeHash(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	var state frontend.Variable = 0
	for j := 0; j < len(inputs); j += 15 {
		chunk := append([]frontend.Variable{state}, inputs[j:min(j+15, len(inputs))]...)
		state = poseidon.Hash(api, chunk...)
	}
	return state
}

// combine merges two aggregate values. The tracks are the 2M per-asset (eq, debt) values, then
// acc, Pi+, and Pi- for CSMT. Pi+ and Pi- (track > 2M) multiply, and the other tracks add.
func combine(api frontend.API, mul bool, a, b frontend.Variable) frontend.Variable {
	if mul {
		return api.Mul(a, b)
	}
	return api.Add(a, b)
}

// Define declares the constraints of one batch.
func (c *TxCentricCircuit) Define(api frontend.API) error {
	n, m, caps := c.Config.NumUsers, c.Config.NumAssets, c.Config.TraceCaps()

	// Fiat-Shamir challenge gamma = Hash(Root_U, Root_T) (Algorithm 4, line 1)
	var gamma frontend.Variable
	if c.Config.IsCSMT {
		gamma = poseidon.Hash(api, c.RootU, c.RootT)
	}

	hashes := make([]frontend.Variable, n)
	tracks := make([][]frontend.Variable, len(c.Agg)) // per-leaf (eq, debt) of each asset, acc, Pi+, Pi-
	for t := range tracks {
		tracks[t] = make([]frontend.Variable, n)
	}

	slot := 0
	for i := 0; i < n; i++ {
		id := api.Add(api.Mul(c.BatchIndex, n), i) // u_i.ID: the global leaf position
		// Liability track: BaseLeafGen, with 64-bit range checks on every equity and debt value
		assets := make([]frontend.Variable, 0, 2*m)
		for k := 0; k < m; k++ {
			eq, debt := c.Equities[i*m+k], c.Debts[i*m+k]
			api.ToBinary(eq, 64)
			api.ToBinary(debt, 64)
			assets = append(assets, eq, debt)
		}
		for t, v := range assets {
			tracks[t][i] = v
		}
		assetCommitment := spongeHash(api, assets)
		if !c.Config.IsCSMT {
			hashes[i] = poseidon.Hash(api, id, assetCommitment)
			continue
		}

		// Trace consistency track: for tx in u_i.trace (Algorithm 4, lines 5-15)
		var acc, piPlus, piMinus, tau frontend.Variable = 0, 1, 1, 0
		for s := 0; s < caps[i]; s++ {
			tx := c.Trace[slot]
			slot++
			h := poseidon.Hash(api, tx.Salt, tx.Asker, tx.Bidder, tx.Pair, tx.AmtAsk, tx.AmtBid)
			// Assert(h_calc == tx.hash), as in Algorithm 4, line 8. tx.Hash is a private input, so h_calc is
			// bound to T_public by tau in the leaf hash and by the grand products checked against Pi_public.
			api.AssertIsEqual(api.Mul(tx.Active, api.Sub(h, tx.Hash)), 0)
			tau = api.Select(tx.Active, poseidon.Hash(api, tau, h), tau) // tau_calc <- Hash(tau_calc, h_calc)
			isBid := api.Mul(tx.Active, api.IsZero(api.Sub(id, tx.Bidder)))
			isAsk := api.Mul(tx.Active, api.Sub(1, isBid), api.IsZero(api.Sub(id, tx.Asker)))
			api.AssertIsEqual(api.Add(isBid, isAsk), tx.Active) // neither bidder nor asker: FAIL
			acc = api.Add(acc, api.Mul(api.Sub(isBid, isAsk), h))
			hGamma := api.Add(h, gamma)
			piPlus = api.Mul(piPlus, api.Select(isBid, hGamma, 1))
			piMinus = api.Mul(piMinus, api.Select(isAsk, hGamma, 1))
		}
		hashes[i] = poseidon.Hash(api, id, assetCommitment, acc, tau)
		tracks[2*m][i], tracks[2*m+1][i], tracks[2*m+2][i] = acc, piPlus, piMinus
	}

	// Merkle tree aggregation over the batch (Algorithm 4, lines 19-28)
	for width := n / 2; width >= 1; width /= 2 {
		for j := 0; j < width; j++ {
			hashes[j] = poseidon.Hash(api, hashes[2*j], hashes[2*j+1])
			for t := range tracks {
				tracks[t][j] = combine(api, t > 2*m, tracks[t][2*j], tracks[t][2*j+1])
			}
		}
	}

	// Authenticate the batch sub-root at position BatchIndex under Root_U
	root := hashes[0]
	pos := api.ToBinary(c.BatchIndex, len(c.Siblings))
	for l, sib := range c.Siblings {
		root = poseidon.Hash(api, api.Select(pos[l], sib, root), api.Select(pos[l], root, sib))
	}
	api.AssertIsEqual(root, c.RootU) // Assert(Root.hash == Root_U)

	// Chain the running aggregate across batches. The verifier opens the final aggregate and
	// checks Root.acc == 0 and Root.Pi+ == Root.Pi- == Pi_public != 0 (Algorithm 4, lines 29-31).
	after := make([]frontend.Variable, len(c.Agg))
	for t := range c.Agg {
		after[t] = combine(api, t > 2*m, c.Agg[t], tracks[t][0])
	}
	api.AssertIsEqual(spongeHash(api, c.Agg), c.AggBefore)
	api.AssertIsEqual(spongeHash(api, after), c.AggAfter)
	return nil
}
