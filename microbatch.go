package itb

// chooseMicroBatch picks the CGO-batch stride for the pixel encoder inner
// loop based on the actual per-invocation payload size.
//
// The batch stride trades two competing costs. Below ~8 MB per invocation
// the dominant cost is the per-call CGO transition overhead, so a large
// batch (fewer calls) wins. Above that threshold the batched hash arrays
// exceed L2, cache-thrash cost overtakes CGO amortisation and a small
// batch (baseline stride) wins again. Very small payloads (≤ 32 KB) do
// not have enough bytes to amortise the up-front hash-array growth to
// the wide stride, so those also fall back to the baseline.
//
// Constants tuned empirically on AMD EPYC 9655P (Zen 5, L2 = 1 MiB/core)
// and Intel i7-11700K (Rocket Lake, L2 = 512 KiB/core — worst-case modern
// Intel for this workload). Modern successors (Alder Lake+, Sapphire
// Rapids, Zen 4+) carry ≥ 1 MiB per-core L2, so the calibration point is
// a lower bound on the acceptable modern-CPU range.
//
// Called once per Encrypt/Decrypt invocation of process{128,256,512}Cfg
// (the same low-level entry both the Message and the Streaming surfaces
// funnel through — Streaming loops call the Single Message entry per
// chunk). Per-chunk payload length reaches this helper as the ordinary
// slice length so the stream shape gets the actual chunk size without
// separate plumbing.
//
// Under Triple Ouroboros the input `data` slice at this entry is one
// third of the user-visible plaintext, so a user 24 MB whole plaintext
// arrives here as ~8 MB per snake — the "≤ 8 MB" branch is the
// crossover point after the /3 factor.
func chooseMicroBatch(payloadBytes int) int {
	switch {
	case payloadBytes <= 32*1024:
		return 512
	case payloadBytes <= 8*1024*1024:
		return 262144
	default:
		return 512
	}
}
