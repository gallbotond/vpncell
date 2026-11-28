//go:build !linux

package client

import (
	"fmt"
	"runtime"
)

// Exec is not implemented on this platform; sessions there are part of #69.
func Exec(ExecOptions) (int, error) {
	return 1, fmt.Errorf("sessions are not supported on %s", runtime.GOOS)
}
