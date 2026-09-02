package forcetier

import (
	"testing"
)

// TestParseUnset verifies that an unset or empty variable resolves to
// auto-dispatch (empty string).
func TestParseUnset(t *testing.T) {
	t.Setenv("ITB_TEST_FORCETIER_VAR", "")
	if got := parse("ITB_TEST_FORCETIER_VAR", "avx512", "scalar"); got != "" {
		t.Fatalf("empty variable: got %q, want \"\"", got)
	}
	// Whitespace-only trims to empty and keeps auto-dispatch.
	t.Setenv("ITB_TEST_FORCETIER_VAR", "   \t ")
	if got := parse("ITB_TEST_FORCETIER_VAR", "avx512", "scalar"); got != "" {
		t.Fatalf("whitespace variable: got %q, want \"\"", got)
	}
}

// TestParseAllowedValues verifies that every allowed value passes
// through, case-insensitively and with surrounding whitespace trimmed.
func TestParseAllowedValues(t *testing.T) {
	allowed := []string{"avx512", "vaesavx2", "avx2", "aesni", "scalar"}
	for _, v := range allowed {
		t.Setenv("ITB_TEST_FORCETIER_VAR", v)
		if got := parse("ITB_TEST_FORCETIER_VAR", allowed...); got != v {
			t.Fatalf("value %q: got %q, want %q", v, got, v)
		}
	}
	// Uppercase input normalises to the lowercase canonical value.
	t.Setenv("ITB_TEST_FORCETIER_VAR", "AVX512")
	if got := parse("ITB_TEST_FORCETIER_VAR", allowed...); got != "avx512" {
		t.Fatalf("uppercase value: got %q, want \"avx512\"", got)
	}
	// Leading/trailing whitespace around a valid value is trimmed.
	t.Setenv("ITB_TEST_FORCETIER_VAR", "  scalar\t")
	if got := parse("ITB_TEST_FORCETIER_VAR", allowed...); got != "scalar" {
		t.Fatalf("padded value: got %q, want \"scalar\"", got)
	}
}

// TestParseUnknownValue verifies that an unrecognised value keeps
// auto-dispatch (empty string) after the stderr warning.
func TestParseUnknownValue(t *testing.T) {
	t.Setenv("ITB_TEST_FORCETIER_VAR", "sse42")
	if got := parse("ITB_TEST_FORCETIER_VAR", "avx512", "avx2", "scalar"); got != "" {
		t.Fatalf("unknown value: got %q, want \"\"", got)
	}
}

// TestAccessorsReturnInitValues verifies that the exported accessors
// report the values resolved at package init. The test process runs
// with the production environment (variables unset), so both report
// auto-dispatch unless the test invocation itself forces a tier.
func TestAccessorsReturnInitValues(t *testing.T) {
	if got := HashTier(); got != hashTier {
		t.Fatalf("HashTier() = %q, want package value %q", got, hashTier)
	}
	if got := InterlockTier(); got != interlockTier {
		t.Fatalf("InterlockTier() = %q, want package value %q", got, interlockTier)
	}
}

// TestWarnf exercises the stderr note formatter used by the
// per-package init overrides. Output goes to stderr; the test only
// requires the call to complete.
func TestWarnf(t *testing.T) {
	Warnf("test-only note: %s tier / %d flags", "scalar", 3)
}
