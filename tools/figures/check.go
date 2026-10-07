package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// Expectation ties one documentation site to one or more computed figures.
//
// Locator is a line-level regular expression anchored on the prose or
// table text around the figure, with one capture group per figure in
// Wants. The expected value never appears in the pattern: a stale
// figure must still locate, so it reports as STALE rather than NOT FOUND.
//
// Sweep selects the matching discipline. An anchored expectation (the
// default) is satisfied by the first line the locator matches. A sweep
// expectation applies to every matching line in the file and requires
// every capture to agree — the discipline for figures the documentation
// restates many times, such as the mask-space cardinality.
type Expectation struct {
	File    string
	Locator *regexp.Regexp
	Wants   []Want
	Sweep   bool
}

// Want names one figure and its expected spelling at this site.
type Want struct {
	Key  string
	Text string
}

// Result is the outcome of one (expectation, want) pair.
type Result struct {
	Status   string // "OK", "STALE", "NOT FOUND"
	File     string
	Line     int
	Key      string
	Expected string
	Found    string // the captured text, or the locator on NOT FOUND
	Matches  int
}

func (r Result) String() string {
	switch r.Status {
	case "OK":
		if r.Matches > 1 {
			return fmt.Sprintf("OK        %s:%d %s = %s (%d matches)", r.File, r.Line, r.Key, r.Expected, r.Matches)
		}
		return fmt.Sprintf("OK        %s:%d %s = %s", r.File, r.Line, r.Key, r.Expected)
	case "STALE":
		return fmt.Sprintf("STALE     %s:%d %s expected %q found %q", r.File, r.Line, r.Key, r.Expected, r.Found)
	default:
		return fmt.Sprintf("NOT FOUND %s %s (%s)", r.File, r.Key, r.Found)
	}
}

// Check evaluates every expectation against the documentation under
// root and returns the results in registry order. The boolean reports
// whether every result is OK.
func Check(root string, exps []Expectation) ([]Result, bool) {
	files := map[string][]string{}
	var results []Result
	ok := true
	for _, e := range exps {
		lines, err := loadLines(files, root, e.File)
		if err != nil {
			results = append(results, Result{Status: "NOT FOUND", File: e.File, Key: e.Wants[0].Key, Found: err.Error()})
			ok = false
			continue
		}
		for _, r := range e.evaluate(lines) {
			if r.Status != "OK" {
				ok = false
			}
			results = append(results, r)
		}
	}
	return results, ok
}

func loadLines(cache map[string][]string, root, file string) ([]string, error) {
	if lines, ok := cache[file]; ok {
		return lines, nil
	}
	fh, err := os.Open(filepath.Join(root, file))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var lines []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	cache[file] = lines
	return lines, nil
}

func (e Expectation) evaluate(lines []string) []Result {
	if e.Locator.NumSubexp() != len(e.Wants) {
		return []Result{{Status: "NOT FOUND", File: e.File, Key: e.Wants[0].Key,
			Found: fmt.Sprintf("pattern has %d capture groups for %d wants", e.Locator.NumSubexp(), len(e.Wants))}}
	}
	results := make([]Result, len(e.Wants))
	for i, w := range e.Wants {
		results[i] = Result{Status: "NOT FOUND", File: e.File, Key: w.Key, Expected: w.Text, Found: e.Locator.String()}
	}
	for n, line := range lines {
		m := e.Locator.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for i, w := range e.Wants {
			r := &results[i]
			r.Matches++
			if r.Status == "STALE" {
				continue
			}
			if m[i+1] != w.Text {
				r.Status, r.Line, r.Found = "STALE", n+1, m[i+1]
				continue
			}
			if r.Status != "OK" {
				r.Status, r.Line, r.Found = "OK", n+1, m[i+1]
			}
		}
		if !e.Sweep {
			break
		}
	}
	return results
}

// Report writes every result, one per line, then a summary line.
func Report(w io.Writer, results []Result) {
	var ok, stale, missing int
	for _, r := range results {
		fmt.Fprintln(w, r.String())
		switch r.Status {
		case "OK":
			ok++
		case "STALE":
			stale++
		default:
			missing++
		}
	}
	fmt.Fprintf(w, "\n%d OK, %d STALE, %d NOT FOUND\n", ok, stale, missing)
}

// expect is the registry constructor for an anchored expectation: one
// file, one pattern, the figures its capture groups must equal, in order.
func expect(file, pattern string, wants ...Want) Expectation {
	return Expectation{File: file, Locator: regexp.MustCompile(pattern), Wants: wants}
}

// sweep is the registry constructor for a sweep expectation.
func sweep(file, pattern string, wants ...Want) Expectation {
	e := expect(file, pattern, wants...)
	e.Sweep = true
	return e
}

// w binds a figure key to its expected spelling.
func w(key, text string) Want { return Want{Key: key, Text: text} }

// q escapes a literal fragment for use inside a locator pattern.
func q(s string) string { return regexp.QuoteMeta(s) }
