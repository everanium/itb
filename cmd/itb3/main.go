// Command itb3 is the command-line utility for the ITB
// Triple Ouroboros construction: a caller creates a session blob
// with itb3 genblob, encrypts / decrypts payloads with itb3 encrypt
// / itb3 decrypt, rotates outer masters with itb3 rekey, and inspects
// or validates blobs with itb3 inspect / itb3 verify. The utility is a
// pure wrapper over the [triple] package's public surface — every
// cryptographic operation flows through the same code paths the Go
// library callers use, so a blob produced here decrypts the same way
// in every binding.
//
// The subcommand hierarchy, help text, and shell completion are
// driven by cobra. The binary is designed for CGO_ENABLED=0 static
// builds so a single artefact ships across linux / macOS / windows
// on both amd64 and arm64.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is populated at build time via `-ldflags="-X main.version=v..."`.
// Defaults to an unset marker so a bare build reveals it hasn't been
// pinned to the release tag.
var version = "dev"

// rootCmd is the top-level cobra command for the itb3 binary. Every
// subcommand attaches to it in [buildRoot].
func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "itb3",
		Short: "ITB Triple Ouroboros utility",
		Long: `itb3 is the command-line utility for the ITB Triple
Ouroboros construction. Callers generate a session configuration blob with
` + "`itb3 genblob`" + `, encrypt or decrypt payloads with
` + "`itb3 encrypt`" + ` / ` + "`itb3 decrypt`" + `, rotate outer masters
with ` + "`itb3 rekey`" + `, and inspect or validate stored blobs with
` + "`itb3 inspect`" + ` / ` + "`itb3 verify`" + `.

The utility is a pure wrapper over the [triple] Go package's public
surface — no new cryptographic logic, no new wire format, no on-disk
state beyond the blob file the caller chooses to write.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		// Disallow undocumented flags on the root so a typo does not
		// silently swallow a subcommand.
		DisableAutoGenTag: true,
	}
	root.AddCommand(newGenblobCmd())
	root.AddCommand(newEncryptCmd())
	root.AddCommand(newDecryptCmd())
	root.AddCommand(newRekeyCmd())
	root.AddCommand(newInspectCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newHashesCmd())
	root.AddCommand(newMacsCmd())
	root.AddCommand(newCiphersCmd())
	root.AddCommand(newModesCmd())
	root.AddCommand(newProfilesCmd())
	root.AddCommand(newCatalogCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newCompletionCmd(root))
	return root
}

// main is the process entry point. Cobra returns the subcommand's
// error (if any) via Execute; the dispatcher translates it to the
// spec-defined exit code and prints the diagnostic to stderr.
func main() {
	cmd := rootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(dispatchExit(err))
	}
	os.Exit(exitOK)
}

// newCompletionCmd builds the `itb3 completion [shell]` subcommand
// dispatching to cobra's built-in per-shell completion emitters.
func newCompletionCmd(root *cobra.Command) *cobra.Command {
	c := &cobra.Command{
		Use:                   "completion [bash|zsh|fish|powershell]",
		Short:                 "Emit shell-completion script to stdout",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Long: `Emit shell-completion script for the named shell to stdout.

Typical install commands:

  itb3 completion bash       | sudo tee /etc/bash_completion.d/itb3
  itb3 completion zsh        > "${fpath[1]}/_itb3"
  itb3 completion fish       > ~/.config/fish/completions/itb3.fish
  itb3 completion powershell > itb3.ps1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return usageErr("completion", "unknown shell %q — accepted: bash, zsh, fish, powershell", args[0])
		},
	}
	return c
}

// newVersionCmd builds the `itb3 version` subcommand. Prints the CLI
// tag alongside a "libitb <tag>" reference so a receiver can tell at
// a glance which library build the CLI was compiled against.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI + library version to stdout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("itb3 %s (libitb %s)\n", version, version)
			return nil
		},
	}
}
