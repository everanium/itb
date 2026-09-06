package aesitbasm

import (
	"encoding/binary"
	"testing"
)

// TestScalarBatchX16Parity verifies that scalarBatchX16 produces byte-exact
// output matching four sequential AESITB128ChainAbsorb13x4 calls on the same
// input material (with appropriate lane mapping).
func TestScalarBatchX16Parity(t *testing.T) {
	// Fixed key for reproducibility (same as test harness elsewhere)
	key := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	seed0 := uint64(0x0102030405060708)
	seed1 := uint64(0x090a0b0c0d0e0f00)

	// Batch-16: single call fills 16 pairs
	var batch16Out [16][2]uint64
	scalarBatchX16(&key, 0, seed0, seed1, &batch16Out)

	// Sequential: four calls to ChainAbsorb13x4, each with 4 lanes offset by groupIdx
	seeds := [4][2]uint64{
		{seed0, seed1},
		{seed0, seed1},
		{seed0, seed1},
		{seed0, seed1},
	}

	// First 4 lanes (groupIdx 0..3)
	dataPtrs0 := [4]*byte{}
	var buf0 [4][13]byte
	for i := 0; i < 4; i++ {
		buf0[i][0] = 0x03
		binary.LittleEndian.PutUint64(buf0[i][1:9], uint64(i))
		dataPtrs0[i] = &buf0[i][0]
	}
	var out0 [4][2]uint64
	scalarBatch(&key, &seeds, &dataPtrs0, 13, &out0)

	// Verify lanes 0..3
	for i := 0; i < 4; i++ {
		if batch16Out[i] != out0[i] {
			t.Errorf("lane %d: batch16 %v != sequential %v", i, batch16Out[i], out0[i])
		}
	}

	// Second 4 lanes (groupIdx 4..7)
	dataPtrs1 := [4]*byte{}
	var buf1 [4][13]byte
	for i := 0; i < 4; i++ {
		buf1[i][0] = 0x03
		binary.LittleEndian.PutUint64(buf1[i][1:9], uint64(4+i))
		dataPtrs1[i] = &buf1[i][0]
	}
	var out1 [4][2]uint64
	scalarBatch(&key, &seeds, &dataPtrs1, 13, &out1)

	for i := 0; i < 4; i++ {
		if batch16Out[4+i] != out1[i] {
			t.Errorf("lane %d: batch16 %v != sequential %v", 4+i, batch16Out[4+i], out1[i])
		}
	}

	// Third 4 lanes (groupIdx 8..11)
	dataPtrs2 := [4]*byte{}
	var buf2 [4][13]byte
	for i := 0; i < 4; i++ {
		buf2[i][0] = 0x03
		binary.LittleEndian.PutUint64(buf2[i][1:9], uint64(8+i))
		dataPtrs2[i] = &buf2[i][0]
	}
	var out2 [4][2]uint64
	scalarBatch(&key, &seeds, &dataPtrs2, 13, &out2)

	for i := 0; i < 4; i++ {
		if batch16Out[8+i] != out2[i] {
			t.Errorf("lane %d: batch16 %v != sequential %v", 8+i, batch16Out[8+i], out2[i])
		}
	}

	// Fourth 4 lanes (groupIdx 12..15)
	dataPtrs3 := [4]*byte{}
	var buf3 [4][13]byte
	for i := 0; i < 4; i++ {
		buf3[i][0] = 0x03
		binary.LittleEndian.PutUint64(buf3[i][1:9], uint64(12+i))
		dataPtrs3[i] = &buf3[i][0]
	}
	var out3 [4][2]uint64
	scalarBatch(&key, &seeds, &dataPtrs3, 13, &out3)

	for i := 0; i < 4; i++ {
		if batch16Out[12+i] != out3[i] {
			t.Errorf("lane %d: batch16 %v != sequential %v", 12+i, batch16Out[12+i], out3[i])
		}
	}
}