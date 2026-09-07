package itb

import (
	"testing"
)

// interlock48_cascade_golden_test.go — golden rank pairs of the aesitb128
// cascade fill. The values pin the wire itself (prepend order of the
// lock components, the 0x04 setup and 0x03 hot-loop tags, the cascade
// depth) on fixed key, components and interlock nonce at every shipped
// key size, independently of the kernel ≡ reference parity the other
// tests provide: a kernel and its reference drifting together would
// pass parity and fail here. Computed through the pure-Go cascade on
// amd64 and verified byte-identical on arm64 NEON.

var cascadeGoldenNonce = func() []byte {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xA5 ^ i*29)
	}
	return nonce
}()

var cascadeGoldenGroups = []uint64{0, 1, 15, 16, 0xFF, 0x0100000000000000, 0xFFFFFFFFFFFFFFFF}

// cascadeGoldenWant[i][j] is the (lo, hi) rank pair of group
// cascadeGoldenGroups[j] under cascadeLockSeedKeys[i] /
// cascadeLockSeedComponents[i] (512 / 1024 / 2048-bit) and
// cascadeGoldenNonce.
var cascadeGoldenWant = [3][7][2]uint64{
	{
		{0x6355a475722e19d5, 0xe9b23a5bbab3d4e9},
		{0x21ef720c07c68066, 0x93a029ea10f16180},
		{0x92375ee7b88106b8, 0x4047c456cbc37cc9},
		{0xe29cbd78bde2aa5e, 0xd2c15e3a1a035ab3},
		{0x5258b50ff8234654, 0x3910b86cb8eeec90},
		{0x3e1413130c23ca5b, 0x22f75dbf53575cee},
		{0xafab0bf795b9e008, 0x13774d430afeb914},
	},
	{
		{0xf84e3090c79606d4, 0x241f634bf64928ee},
		{0xeef65a19f886a9a3, 0xbd1350cbc18b4c80},
		{0x0a34d05227658e7f, 0x434114171c438a00},
		{0x6e64d1dfce9d2809, 0x5d14f64ca80b7d99},
		{0x3f1df24acb09d260, 0x68885b9720160460},
		{0x5f737b2c97228a2a, 0xeb09c02da5e7dafd},
		{0xbbffca6856730141, 0x6792a88ebc28217a},
	},
	{
		{0x1ba9fafd7da38b97, 0x7ecf5039663faf50},
		{0xce4959bceddd0dd0, 0x12e7588a4f0cc3a6},
		{0x9f53df606d49f27a, 0xcb5a323ceeb4b692},
		{0x972ec0354e18d781, 0x8e76e661895771e9},
		{0x41ae92234aef5b4e, 0x33300298a6629137},
		{0x097d2c4e6c21f4df, 0x4376defe766c1f91},
		{0xc04b042e7c359654, 0x067d6768fe155123},
	},
}

// TestCascadeFillGolden pins the cascade fill of every shipped key size
// to the golden rank pairs through the shipped builder — fillRanks (the
// single-lane cascade) and, when armed, fillRanksSuper (the batch-16
// kernel) on the batch holding each group.
func TestCascadeFillGolden(t *testing.T) {
	for i, key := range cascadeLockSeedKeys {
		seed := cascadeLockSeed(t, key, cascadeLockSeedComponents[i], true)
		bp := buildLockBatchPRF48_128(seed, cascadeGoldenNonce)
		for j, g := range cascadeGoldenGroups {
			buf := cascadeFillBlock(g)
			var got [2]uint64
			bp.fillRanks(buf[:], g, got[:])
			if got != cascadeGoldenWant[i][j] {
				t.Errorf("key %d group %#x: fillRanks {%#016x, %#016x}, golden {%#016x, %#016x}",
					i, g, got[0], got[1], cascadeGoldenWant[i][j][0], cascadeGoldenWant[i][j][1])
			}
			if bp.fillRanksSuper != nil {
				base := g &^ 0xF
				var scratch lockFillScratch48
				var super [8 * lockBatchFactor48Max]uint64
				bp.fillRanksSuper(&scratch, base, super[0:32])
				lane := int(g - base)
				if super[2*lane] != cascadeGoldenWant[i][j][0] || super[2*lane+1] != cascadeGoldenWant[i][j][1] {
					t.Errorf("key %d group %#x: fillRanksSuper lane %d {%#016x, %#016x}, golden {%#016x, %#016x}",
						i, g, lane, super[2*lane], super[2*lane+1], cascadeGoldenWant[i][j][0], cascadeGoldenWant[i][j][1])
				}
			}
		}
	}
}
