//go:build !linux

package profile

import "os"

// statUID reports the owner as unknown on other platforms, so the
// root-owner check in checkRootOnly stays Linux-only for now (#68). How
// Windows and macOS check who may write profile files is part of #69.
func statUID(os.FileInfo) (uid uint32, ok bool) {
	return 0, false
}
