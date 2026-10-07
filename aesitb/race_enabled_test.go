//go:build race

package aesitb

// raceEnabled reports a -race build, whose instrumentation moves the
// filler's stack seed to the heap; allocation pins skip under it.
const raceEnabled = true
