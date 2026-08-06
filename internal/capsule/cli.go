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

func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printCapsulectlUsage(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		printCapsulectlUsage(stdout)
		return 0
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "capsulectl %s\n", currentVersion())
		return 0
	}
	command := args[0]
	if command != "plan" && command != "resolve" && command != "intake" && command != "check" && command != "bundle" && command != "run" {
		fmt.Fprintf(stderr, "capsulectl: unknown command %s\n", command)
		printCapsulectlUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	specFilename := flags.String("spec", "", "capsule specification")
	var sourceRevision, outputDirectory, packageValue *string
	var devDependency, removePackage *bool
	if command == "resolve" {
		packageValue = flags.String("package", "", "exact package@version to add or package name to remove")
		outputDirectory = flags.String("output", "", "new candidate manifest and lockfile directory")
		devDependency = flags.Bool("dev", false, "add to devDependencies")
		removePackage = flags.Bool("remove", false, "remove the named direct dependency")
	}
	if command == "bundle" {
		sourceRevision = flags.String("source-revision", "", "reviewed full Git commit SHA")
		outputDirectory = flags.String("output", "", "new promotion bundle directory")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *specFilename == "" {
		fmt.Fprintln(stderr, "capsulectl: --spec is required")
		return 2
	}
	loaded, err := LoadSpec(*specFilename)
	if err != nil {
		fmt.Fprintf(stderr, "capsulectl: %v\n", err)
		return 1
	}
	var value any
	switch command {
	case "plan":
		var image string
		var state *State
		image, state, err = loaded.ResolveImageAndState()
		if err == nil {
			var plan Plan
			plan, err = RuntimePlan(loaded, image, flags.Args())
			if state != nil {
				plan.InputSHA256 = state.InputSHA256
			}
			value = plan
		}
	case "check":
		if len(flags.Args()) != 0 {
			err = errors.New("check does not accept a command")
			break
		}
		value, err = Check(ctx, loaded, NewHTTPFeedFetcher(20*time.Second), time.Now())
	case "resolve":
		if len(flags.Args()) != 0 || *packageValue == "" || *outputDirectory == "" {
			err = errors.New("resolve requires --package and --output and does not accept a command")
			break
		}
		var engine Engine
		engine, err = DiscoverEngine(ctx)
		if err == nil {
			defer engine.Close()
			value, err = Resolve(ctx, engine, loaded, ResolveRequest{
				Package:         *packageValue,
				OutputDirectory: *outputDirectory,
				Dev:             *devDependency,
				Remove:          *removePackage,
			}, NewHTTPFeedFetcher(20*time.Second), time.Now(), stderr, stderr)
		}
	case "intake":
		if len(flags.Args()) != 0 {
			err = errors.New("intake does not accept a command")
			break
		}
		var engine Engine
		engine, err = DiscoverEngine(ctx)
		if err == nil {
			defer engine.Close()
			value, err = Intake(ctx, engine, loaded, NewHTTPFeedFetcher(20*time.Second), time.Now(), stderr, stderr)
		}
	case "bundle":
		if len(flags.Args()) != 0 || *sourceRevision == "" || *outputDirectory == "" {
			err = errors.New("bundle requires --source-revision and --output and does not accept a command")
			break
		}
		var engine Engine
		engine, err = DiscoverEngine(ctx)
		if err == nil {
			defer engine.Close()
			value, err = PreparePromotion(ctx, engine, loaded, NewHTTPFeedFetcher(20*time.Second), *sourceRevision, *outputDirectory, time.Now(), stderr, stderr)
		}
	case "run":
		var engine Engine
		engine, err = DiscoverEngine(ctx)
		if err == nil {
			defer engine.Close()
			err = Run(ctx, engine, loaded, flags.Args(), NewHTTPFeedFetcher(20*time.Second), time.Now(), stdin, stdout, stderr)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "capsulectl: %v\n", err)
		var commandError CommandError
		if errors.As(err, &commandError) && commandError.Code > 0 && commandError.Code < 126 {
			return commandError.Code
		}
		return 1
	}
	if command == "run" {
		return 0
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "capsulectl: write result: %v\n", err)
		return 1
	}
	return 0
}
