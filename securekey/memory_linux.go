//go:build linux

package securekey

import "golang.org/x/sys/unix"

func Supported() bool { return true }

func protectMemory(b []byte) error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Mlock(b)
}

func unprotectMemory(b []byte) {
	_ = unix.Munlock(b)
}
