package main

import (
	"fmt"
	"os"
)

func runOVPNHook(args []string) int {
	fmt.Fprintln(os.Stderr, "ovpn-hook: OpenVPN support is not built yet")
	return 1
}
