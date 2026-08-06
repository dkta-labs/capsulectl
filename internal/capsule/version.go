package capsule

import (
	"fmt"
	"io"
)

// Version is set at build time for release binaries.
var Version = "dev"

func printCapsulectlUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: capsulectl <command> [options]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  plan     Print the hardened runtime invocation")
	fmt.Fprintln(output, "  resolve  Produce reviewed candidate dependency files")
	fmt.Fprintln(output, "  intake   Build and record a credential-blind dependency image")
	fmt.Fprintln(output, "  check    Verify inputs, image binding, provenance, and live feeds")
	fmt.Fprintln(output, "  bundle   Create a short-lived promotion bundle")
	fmt.Fprintln(output, "  run      Execute a command inside the verified capsule")
	fmt.Fprintln(output, "  version  Print the capsulectl version")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Run 'capsulectl <command> -h' for command options.")
}

func printPromoterUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: capsule-promoter --bundle FILE --destination REGISTRY/REPOSITORY:TAG --source-revision SHA --provenance-out FILE")
}
