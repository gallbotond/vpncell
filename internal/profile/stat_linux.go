package profile

import (
	"os"
	"syscall"
)

// statUID returns the file's owner. ok is always true on Linux: an owner
// that cannot be read counts as "not root" (uid 2^32-1), so checkRootOnly
// refuses the file.
func statUID(st os.FileInfo) (uid uint32, ok bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Uid, true
	}
	return 1<<32 - 1, true
}
