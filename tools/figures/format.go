package main

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Rendering helpers. Each documentation site states a figure in one
// spelling — thousands separators or not, a leading tilde, a Unicode
// minus — and the expectation registry names the spelling explicitly,
// so the checker compares strings rather than parsed numbers.

// comma renders an integer with thousands separators: 1225 → "1,225".
func comma(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func plain(n int) string { return strconv.Itoa(n) }

// fixed renders x with d decimals.
func fixed(x float64, d int) string { return strconv.FormatFloat(x, 'f', d, 64) }

// trunc renders x truncated (not rounded) to d decimals.
func trunc(x float64, d int) string {
	p := math.Pow(10, float64(d))
	return strconv.FormatFloat(math.Floor(x*p)/p, 'f', d, 64)
}

// ratio renders a multiplier: one decimal below 100 with a whole
// value written without the decimal, integer above ("26.9×", "32×",
// "415×").
func ratio(x float64) string {
	if x < 100 {
		return strings.TrimSuffix(fixed(x, 1), ".0") + "×"
	}
	return fixed(x, 0) + "×"
}

// ratioBare renders a multiplier as ratio does, without the sign.
func ratioBare(x float64) string { return strings.TrimSuffix(ratio(x), "×") }

// commaBig renders a big integer with thousands separators.
func commaBig(n *big.Int) string {
	s := n.String()
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// kb renders a byte count in decimal kilobytes to one decimal: 7880 → "7.9".
func kb(bytes int) string { return fixed(float64(bytes)/1000, 1) }

// pct renders a signed percentage change to one decimal with the
// Unicode minus the documentation uses: −62.7.
func pct(from, to int) string {
	x := (float64(to) - float64(from)) / float64(from) * 100
	s := fixed(x, 1)
	return strings.Replace(s, "-", "−", 1)
}

// sci renders x in the documentation's `m × 10⁻ᵉ` notation with d
// significant decimals: 1.4956e-05 → "1.5 × 10⁻⁵".
func sci(x float64, d int) string {
	e := int(math.Floor(math.Log10(x)))
	m := x / math.Pow(10, float64(e))
	return fmt.Sprintf("%s × 10%s", fixed(m, d), superscript(e))
}

func superscript(n int) string {
	digits := []rune("⁰¹²³⁴⁵⁶⁷⁸⁹")
	var b strings.Builder
	if n < 0 {
		b.WriteRune('⁻')
		n = -n
	}
	for _, r := range strconv.Itoa(n) {
		b.WriteRune(digits[r-'0'])
	}
	return b.String()
}

// dims renders "W × H" with the documentation's multiplication sign.
func dims(side int) string { return fmt.Sprintf("%d × %d", side, side) }

// pow2 renders "2^<exp>"; pow2c the thousands-separated form.
func pow2(exp int) string  { return "2^" + plain(exp) }
func pow2c(exp int) string { return "2^" + comma(exp) }
