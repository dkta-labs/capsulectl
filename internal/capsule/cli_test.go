package capsule

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestMainHelpAndVersion(t *testing.T) {
	previous := Version
	Version = "1.2.3-test"
	t.Cleanup(func() { Version = previous })

	for _, test := range []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{name: "help", args: []string{"help"}, wantCode: 0, want: "Commands:"},
		{name: "long help", args: []string{"--help"}, wantCode: 0, want: "capsulectl <command>"},
		{name: "version", args: []string{"version"}, wantCode: 0, want: "capsulectl 1.2.3-test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Main(context.Background(), test.args, strings.NewReader(""), &stdout, &stderr)
			if code != test.wantCode {
				t.Fatalf("exit code = %d, want %d; stderr=%q", code, test.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) {
				t.Fatalf("stdout %q does not contain %q", stdout.String(), test.want)
			}
		})
	}
}

func TestMainWithoutCommandExplainsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), nil, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "capsulectl <command>") {
		t.Fatalf("stderr lacks usage: %q", stderr.String())
	}
}

func TestPromoterHelpAndVersion(t *testing.T) {
	previous := Version
	Version = "1.2.3-test"
	t.Cleanup(func() { Version = previous })

	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"--help"}, want: "capsule-promoter --bundle"},
		{args: []string{"--version"}, want: "capsule-promoter 1.2.3-test"},
	} {
		var stdout, stderr bytes.Buffer
		code := PromoterMain(context.Background(), test.args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("args %v exit code = %d; stderr=%q", test.args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("args %v stdout %q does not contain %q", test.args, stdout.String(), test.want)
		}
	}
}
