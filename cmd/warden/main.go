// Command warden is the Warden CLI. All logic lives in internal/cli.
package main

import (
	"os"

	"github.com/rviscuso/warden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
