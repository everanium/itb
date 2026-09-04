package main

// Registry-listing subcommands: `hashes`, `macs`, `ciphers`, `modes`,
// `profiles`, and the unified `catalog` dump. Every list is driven by
// a runtime query against the shipped registry (`hashes.Registry` /
// `hashes.FullView()` / `hashes.Names()`, `macs.Registry`, plus
// `triple.Profiles()` for the profile catalogue) so the output stays
// current as the shipped catalogues grow without a CLI code change.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/triple"
)

// newHashesCmd — `itb3 hashes`.
func newHashesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hashes",
		Short: "List shipped hash primitives (one per line)",
		Args:  cobra.NoArgs,
		Long: `Enumerate every shipped entry in hashes.Registry, one primitive per
line to stdout, in the registry's canonical order.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, spec := range hashes.Registry {
				fmt.Println(spec.Name)
			}
			return nil
		},
	}
}

// newMacsCmd — `itb3 macs`.
func newMacsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "macs",
		Short: "List shipped MAC primitives (one per line)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, spec := range macs.Registry {
				fmt.Println(spec.Name)
			}
			return nil
		},
	}
}

// newCiphersCmd — `itb3 ciphers`.
func newCiphersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ciphers",
		Short: "List shipped wrapper outer ciphers (one per line)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range hashes.Names() {
				fmt.Println(name)
			}
			return nil
		},
	}
}

// newModesCmd — `itb3 modes`.
func newModesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modes",
		Short: "List CLI mode positionals (one per line)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range cliModeNames() {
				fmt.Println(name)
			}
			return nil
		},
	}
}

// newProfilesCmd — `itb3 profiles`.
func newProfilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List registered profile names (one per line)",
		Args:  cobra.NoArgs,
		Long: `Enumerate every name in the profile catalogue — the shipped profiles
plus any registered in this process — one per line to stdout, in
ascending lexicographic order. The list is informational: itb3
generates its own profile per genblob call, and every blob carries its
resolved profile record, so no catalogue name is needed on the
encrypt / decrypt side.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range triple.Profiles() {
				fmt.Println(name)
			}
			return nil
		},
	}
}

// cliModeNames returns the CLI-visible mode positional tokens in
// their canonical order.
func cliModeNames() []string {
	return []string{"mac", "nomac", "aead", "noaead"}
}

// newCatalogCmd — `itb3 catalog`. Unified multi-section dump; every
// value is queried at runtime from the shipped registries so the
// output stays correct as the catalogue grows.
func newCatalogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "Emit a unified multi-section dump of accepted inputs",
		Args:  cobra.NoArgs,
		Long: `Unified catalogue dump — one call gets the full picture of what the
CLI accepts. Every value is populated by querying the shipped
runtime registries; the listing stays current as new primitives are
added.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			printCatalog()
			return nil
		},
	}
}

// printCatalog writes the plain-text catalogue to stdout. Kept as a
// separate helper so a downstream `--json` mode could reuse the same
// value-collection paths under a different renderer.
func printCatalog() {
	// Registry snapshots.
	view := hashes.FullView()
	hashNames := make([]string, 0, len(view))
	for _, info := range view {
		hashNames = append(hashNames, info.Name)
	}
	macNames := make([]string, 0, len(macs.Registry))
	for _, spec := range macs.Registry {
		macNames = append(macNames, spec.Name)
	}
	cipherNames := hashes.Names()

	// Mixed-pool sizes are queried at runtime from the same
	// hashes.Registry filter the genblob random draw uses.
	mixed128 := filterHashesByWidth(hashes.W128)
	mixed256 := filterHashesByWidth(hashes.W256)
	mixed512 := filterHashesByWidth(hashes.W512)

	fmt.Printf("Modes:       %s\n", strings.Join(cliModeNames(), ", "))
	fmt.Printf("Primitives:  %s\n", strings.Join(hashNames, ", "))
	fmt.Printf("Mixed:       mixed128 (%d prims), mixed256 (%d prims), mixed512 (%d prims)\n",
		len(mixed128), len(mixed256), len(mixed512))
	fmt.Printf("KeyBits:     512, 1024, 2048  (default 1024)\n")
	fmt.Printf("NonceBits:   128, 256, 512  (default 512)\n")
	fmt.Printf("BarrierFill: 1, 2, 4, 8, 16, 32  (default 1)\n")
	fmt.Printf("ChunkSize:   1-64 MB  (default 16 MiB; used for aead/noaead modes)\n")
	fmt.Printf("MACs:        %s\n", strings.Join(macNames, ", "))
	fmt.Printf("Ciphers:     %s\n", strings.Join(cipherNames, ", "))
	fmt.Printf("Segments:    coprime-504 positive int (default %d)\n", parallax.DefaultSegmentSize)
	fmt.Printf("Toggles:     -p (parallax palette), -w (wrapper cipher)\n")
	fmt.Printf("Profiles:    %s\n", strings.Join(triple.Profiles(), ", "))
	fmt.Println()
	fmt.Println("Example invocations:")
	fmt.Println("  itb3 genblob mac areion512 -k 1024 -m hmac-sha256 -p aescmac,chacha20,siphash24 -s 4093 -w chacha20")
	fmt.Println("  itb3 genblob aead mixed256 -k 2048 -m kmac256 -c 16")
	fmt.Println("  itb3 genblob nomac blake3 -k 1024")
}

// filterHashesByWidth returns the shipped-registry primitive names
// whose width matches the argument. Consumed by the mixed-pool sizing
// in [printCatalog] and by the genblob random draw.
func filterHashesByWidth(w hashes.Width) []string {
	var out []string
	for _, spec := range hashes.Registry {
		if spec.Width == w {
			out = append(out, spec.Name)
		}
	}
	return out
}
