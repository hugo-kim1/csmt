package circuit

// Config holds the circuit shape and the benchmark settings of one scenario.
type Config struct {
	// Name labels the scenario in the output.
	Name string

	// IsCSMT adds the trace consistency track: the accumulator, the trace commitment, and the
	// role-separated grand products. When false, the circuit is the baseline zk-SMT.
	IsCSMT bool

	// NumUsers is the batch size N, the number of user leaves in one batch circuit.
	NumUsers int

	// NumAssets is M, the number of asset types per user.
	NumAssets int

	// NumTxs is K, the number of trades in the batch within the buffer window.
	NumTxs int

	// GlobalDepth is the depth of the global Merkle tree. Depth 28 holds about 268 million accounts.
	GlobalDepth int

	// NumIterations is how many times the benchmark proves the batch.
	NumIterations int
}

// Trade is a benchmark trade between two users of the batch, given by their leaf indices.
type Trade struct{ Asker, Bidder int }

// Trades returns the K benchmark trades. Trade t pairs user t (asker) with user N-1-t (bidder),
// so the K trades involve 2K distinct users as long as K <= N/2.
func (cfg Config) Trades() []Trade {
	trades := make([]Trade, cfg.NumTxs)
	for t := range trades {
		trades[t] = Trade{Asker: t, Bidder: cfg.NumUsers - 1 - t}
	}
	return trades
}

// TraceCaps returns the trace capacity of each user leaf: the number of trade legs (|u_i.trace|)
// that the circuit reserves for it. The capacities sum to 2K.
func (cfg Config) TraceCaps() []int {
	caps := make([]int, cfg.NumUsers)
	if cfg.IsCSMT {
		for _, tr := range cfg.Trades() {
			caps[tr.Asker]++
			caps[tr.Bidder]++
		}
	}
	return caps
}
