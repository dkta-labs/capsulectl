package capsule

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

func PromoterMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 {
		switch args[0] {
		case "-h", "--help":
			printPromoterUsage(stdout)
			return 0
		case "-version", "--version":
			fmt.Fprintf(stdout, "capsule-promoter %s\n", Version)
			return 0
		}
	}
	flags := flag.NewFlagSet("capsule-promoter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundle := flags.String("bundle", "", "promotion bundle JSON")
	destination := flags.String("destination", "", "explicit non-latest registry tag")
	sourceRevision := flags.String("source-revision", "", "reviewed full Git commit SHA")
	provenanceOutput := flags.String("provenance-out", "", "promoted SLSA provenance output")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *bundle == "" || *destination == "" || *sourceRevision == "" || *provenanceOutput == "" || len(flags.Args()) != 0 {
		printPromoterUsage(stderr)
		return 2
	}
	engine, err := DiscoverPromoterEngine(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "capsule-promoter: %v\n", err)
		return 1
	}
	result, err := Promote(ctx, engine, *bundle, *destination, *sourceRevision, *provenanceOutput, time.Now(), stderr, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "capsule-promoter: %v\n", err)
		var commandError CommandError
		if errors.As(err, &commandError) && commandError.Code > 0 && commandError.Code < 126 {
			return commandError.Code
		}
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "capsule-promoter: write result: %v\n", err)
		return 1
	}
	return 0
}
