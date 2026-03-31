package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/jcouture/ghostscan/internal/exitcode"
)

var benchExitCode int

func BenchmarkExecute(b *testing.B) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "CleanRepo", args: []string{"--silent", "--no-color", filepath.Join("..", "testdata", "clean")}},
		{name: "MixedRepo", args: []string{"--silent", "--no-color", filepath.Join("..", "testdata", "mixed")}},
		{name: "VerboseMixedRepo", args: []string{"--silent", "--no-color", "--verbose", filepath.Join("..", "testdata", "mixed")}},
	}

	ctx := context.Background()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stdout.Reset()
				stderr.Reset()

				benchExitCode = execute(ctx, tc.args, &stdout, &stderr)
				if benchExitCode != exitcode.Success && benchExitCode != exitcode.FindingsDetected {
					b.Fatalf("unexpected exit code %d: %s", benchExitCode, stderr.String())
				}
			}
		})
	}
}
