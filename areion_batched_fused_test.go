package itb

import (
	"testing"

	"github.com/everanium/itb/internal/areionasm"
)

// The batched arm of MakeAreionSoEM{256,512}Hash has two routes: the
// single-lane fused cascade kernel per lane (the ITB buf shapes on a
// host with an Areion assembly tier) and the four-way SoEM over the
// batched permutation (every other length, and builds without such a
// tier). Both must reproduce the single arm lane by lane over the
// equal-length lanes ITB feeds; the tests below pin that on every
// build and forced tier.

var areionBatchedLens = []int{0, 1, 5, 13, 20, 24, 36, 48, 68, 100}

func areionBatchedData(lens [4]int) (data [4][]byte) {
	for lane := range data {
		buf := make([]byte, lens[lane])
		for i := range buf {
			buf[i] = byte(lane*37 + i*3 + lens[lane])
		}
		data[lane] = buf
	}
	return data
}

func TestAreionBatchedArmMatchesSingle256(t *testing.T) {
	single, batched, _ := MakeAreionSoEM256Hash()
	var seeds [4][4]uint64
	for lane := range seeds {
		for i := range seeds[lane] {
			seeds[lane][i] = uint64(lane*4+i+1) * 0x9E3779B97F4A7C15
		}
	}
	check := func(lens [4]int) {
		data := areionBatchedData(lens)
		got := batched(&data, seeds)
		for lane := range got {
			if want := single(data[lane], seeds[lane]); got[lane] != want {
				t.Errorf("lens %v lane %d: batched %x, single %x", lens, lane, got[lane], want)
			}
		}
	}
	for _, n := range areionBatchedLens {
		check([4]int{n, n, n, n})
	}
	if areionasm.FusedAvailable() {
		data := areionBatchedData([4]int{20, 20, 20, 20})
		if allocs := testing.AllocsPerRun(50, func() { batched(&data, seeds) }); allocs != 0 {
			t.Errorf("fused route allocates: %v allocs/op", allocs)
		}
	}
}

func TestAreionBatchedArmMatchesSingle512(t *testing.T) {
	single, batched, _ := MakeAreionSoEM512Hash()
	var seeds [4][8]uint64
	for lane := range seeds {
		for i := range seeds[lane] {
			seeds[lane][i] = uint64(lane*8+i+1) * 0x9E3779B97F4A7C15
		}
	}
	check := func(lens [4]int) {
		data := areionBatchedData(lens)
		got := batched(&data, seeds)
		for lane := range got {
			if want := single(data[lane], seeds[lane]); got[lane] != want {
				t.Errorf("lens %v lane %d: batched %x, single %x", lens, lane, got[lane], want)
			}
		}
	}
	for _, n := range areionBatchedLens {
		check([4]int{n, n, n, n})
	}
	if areionasm.FusedAvailable() {
		data := areionBatchedData([4]int{20, 20, 20, 20})
		if allocs := testing.AllocsPerRun(50, func() { batched(&data, seeds) }); allocs != 0 {
			t.Errorf("fused route allocates: %v allocs/op", allocs)
		}
	}
}
