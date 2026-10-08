// Package cpuid is the single reader of host CPU features for the ITB
// assembly dispatch. Every kernel package takes its capability flags
// from the fields below instead of reading an upstream feature package
// itself, so one OS-state rule applies to every tier.
//
// The fields are resolved once at package init and are not changed
// afterwards. On amd64 they come from github.com/klauspost/cpuid/v2,
// whose AVX / AVX2 / AVX-512 bits already require the matching OS
// register state (XGETBV XCR0). On arm64 they come from
// golang.org/x/sys/cpu, which covers SVE2 and every arm64 OS the
// kernels build for, plus the Linux AT_HWCAP2 bit for SVE bit-permute.
// On any other GOARCH they keep the values the x/sys fields report
// there.
//
// The VAES CPUID bit is one bit for the VEX.256 and EVEX encodings; the
// fields expose it only paired with the register state the encoding
// needs: [VAESYMM] with AVX2, [VAESZMM] with AVX-512F.
package cpuid

// x86 feature fields. All are false off x86.
var (
	// SSE2 is architectural on amd64. A false value there means the
	// detection backend reported nothing (for instance a build under a
	// tag that compiles the backend's detection out).
	SSE2 bool

	// AESNI reports the legacy-SSE AES-NI instructions.
	AESNI bool

	// AVX2 reports AVX2 with OS-enabled YMM state.
	AVX2 bool

	// AVX512F, AVX512BW, AVX512VL and AVX512DQ report the AVX-512
	// subsets with OS-enabled opmask and ZMM state.
	AVX512F  bool
	AVX512BW bool
	AVX512VL bool
	AVX512DQ bool

	// VAESYMM reports VAES usable in its VEX.256 (YMM) form: the VAES
	// bit together with AVX2.
	VAESYMM bool

	// VAESZMM reports VAES usable in its EVEX.512 (ZMM) form: the VAES
	// bit together with AVX-512F.
	VAESZMM bool

	// BMI2 reports the BMI2 instructions (PEXT / PDEP among them),
	// whatever their latency.
	BMI2 bool

	// BMI2Fast reports BMI2 with PEXT / PDEP executed in hardware at
	// fixed latency. AMD and Hygon parts before family 0x19 (Zen 1 /
	// Zen 2 and older) execute the two instructions in microcode with
	// data-dependent latency and report false.
	BMI2Fast bool

	// X86Vendor and X86Family describe the host for diagnostics.
	X86Vendor string
	X86Family int
)

// arm64 feature fields. All are false off arm64.
var (
	// ASIMD reports Advanced SIMD (NEON).
	ASIMD bool

	// ARMAES reports the ARMv8 Cryptography Extension AES instructions.
	ARMAES bool

	// SVE2BitPerm reports SVE2 together with the optional bit-permute
	// extension (FEAT_SVE_BitPerm: BEXT / BDEP).
	SVE2BitPerm bool
)

// vendorAMD and vendorHygon are the vendor names [bmi2Fast] treats as
// microcoded-PEXT parts below family 0x19.
const (
	vendorAMD   = "AMD"
	vendorHygon = "Hygon"
)

// bmi2Fast reports whether PEXT / PDEP run at fixed latency on a host
// with the given BMI2 bit, vendor and family. AMD families below 0x19
// (Zen 1 / Zen 2 at 0x17 and the earlier BMI2 parts) and Hygon (Zen 1
// derived, family 0x18) microcode both instructions.
func bmi2Fast(bmi2 bool, vendor string, family int) bool {
	if !bmi2 {
		return false
	}
	if (vendor == vendorAMD || vendor == vendorHygon) && family < 0x19 {
		return false
	}
	return true
}

// vaesUsable reports whether the VAES bit is usable in a form whose
// register state is reported by state (AVX2 for YMM, AVX-512F for ZMM).
func vaesUsable(vaes, state bool) bool { return vaes && state }
