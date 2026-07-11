package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/slackhq/nebula/keyring"
)

func main() {
	description := flag.String("description", "nebula-host-key", "key description in the service session keyring")
	flag.Parse()
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		fatal(err)
	}
	if len(payload) == 1<<20 {
		fatal(fmt.Errorf("key payload exceeds 1 MiB"))
	}
	if _, err := keyring.Put(*description, payload); err != nil {
		fatal(err)
	}
	for i := range payload {
		payload[i] = 0
	}

	if flag.NArg() > 0 {
		cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatal(fmt.Errorf("run service: %w", err))
		}
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "nebula-keyring: %v\n", err)
	os.Exit(1)
}
