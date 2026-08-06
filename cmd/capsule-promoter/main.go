package main

import (
	"context"
	"os"

	"github.com/dkta-labs/capsulectl/internal/capsule"
)

func main() {
	os.Exit(capsule.PromoterMain(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
