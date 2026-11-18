// Command proxy-checker checks HTTP, HTTPS, SOCKS4 and SOCKS5 proxies.
package main

import (
	"os"

	"github.com/quanticdata-io/proxy-checker/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.OSEnv()))
}
