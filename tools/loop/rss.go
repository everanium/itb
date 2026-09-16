package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// readRSS returns the process's current resident set and its
// high-water mark in bytes, read from /proc/self/status (VmRSS and
// VmHWM, reported in kB). Both are zero on a platform without that
// file, which the summary renders as-is: the figures are informational
// and never enter the verdict.
func readRSS() (current, peak uint64) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			current = statusKB(line)
		case strings.HasPrefix(line, "VmHWM:"):
			peak = statusKB(line)
		}
	}
	return current, peak
}

// statusKB parses one "Vm...:   1234 kB" line of /proc/self/status
// into bytes; zero on any parse failure.
func statusKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return n * 1024
}
