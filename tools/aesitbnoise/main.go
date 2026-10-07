// Command aesitbnoise streams the aesitb128 DRBG noise filler to stdout
// for an external statistical battery. It covers that arm alone: every
// other DRBG fill name is a standard keystream or crypto/rand, whose
// output is analysed elsewhere, while the AES-ITB filler is a
// construction of this repository.
//
//	go run ./tools/aesitbnoise -mode=fresh | RNG_test stdin -tlmax 512GB -multithreaded
//
// Modes:
//
//	fresh     aesitb.FillNoise in calls of -call bytes (default 6 MiB, one
//	          third of the container of a 16 MB message), with a fresh
//	          key and nonce per call — the shipped use
//	fixed     one key and one nonce for the whole run, one unbroken
//	          counter stream through the shipped kernels — stricter than
//	          any shipped use, where one key covers a single call
//	oneblock  negative control: the three-round one-block form (empty
//	          data slot, counter in the seed slot) the filler avoids by
//	          carrying the nonce in the data slot; a battery that cannot
//	          flag it cannot vouch for the shipped form
//	csprng    positive control: crypto/rand through the same pipe
//
// The output is raw bytes with no framing.
package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/everanium/itb/aesitb"
	"github.com/everanium/itb/internal/aesitbasm"
)

func main() {
	mode := flag.String("mode", "fresh", "fresh | fixed | oneblock | csprng")
	call := flag.Int("call", 6<<20, "bytes per FillNoise call in fresh mode")
	flag.Parse()
	if *call < 16 {
		fmt.Fprintln(os.Stderr, "aesitbnoise: -call must be at least 16")
		os.Exit(2)
	}

	// Each stream returns when a write fails, which is how a run ends:
	// the reader closes the pipe.
	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	switch *mode {
	case "fresh":
		streamFresh(w, *call)
	case "fixed":
		streamFixed(w)
	case "oneblock":
		streamOneBlock(w)
	case "csprng":
		streamCSPRNG(w)
	default:
		fmt.Fprintf(os.Stderr, "aesitbnoise: unknown -mode %q\n", *mode)
		os.Exit(2)
	}
}

func streamFresh(w *bufio.Writer, call int) error {
	buf := make([]byte, call)
	for {
		if err := aesitb.FillNoise(buf); err != nil {
			fmt.Fprintln(os.Stderr, "aesitbnoise:", err)
			os.Exit(1)
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
}

func streamFixed(w *bufio.Writer) error {
	var key [16]byte
	var nonce [32]byte
	mustRead(key[:])
	mustRead(nonce[:])
	s := aesitbasm.NewNoiseSchedule(&key, &nonce)
	buf := make([]byte, 6<<20)
	blocks := uint64(len(buf) / 16)
	var lo, hi uint64
	for {
		aesitbasm.NoiseFill(&s, buf, lo, hi)
		next := lo + blocks
		if next < lo {
			hi++
		}
		lo = next
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
}

func streamOneBlock(w *bufio.Writer) error {
	var key [16]byte
	mustRead(key[:])
	var block [16]byte
	for ctr := uint64(0); ; ctr++ {
		block = aesitb.HashGeneric(key, nil, ctr, 0)
		if _, err := w.Write(block[:]); err != nil {
			return err
		}
	}
}

func streamCSPRNG(w *bufio.Writer) error {
	buf := make([]byte, 6<<20)
	for {
		mustRead(buf)
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
}

func mustRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintln(os.Stderr, "aesitbnoise:", err)
		os.Exit(1)
	}
}
