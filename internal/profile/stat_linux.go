package profile

import (
	"os"
	"syscall"
)

func statUID(st os.FileInfo) uint32 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Uid
	}
	return 1<<32 - 1
}
