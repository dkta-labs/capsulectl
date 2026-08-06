package main

import (
	"context"
	"os"

	"github.com/dkta-labs/capsulectl/internal/capsule"
)

func main() {
	os.Exit(capsule.Main(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
