//go:build linux

package securekey

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func Supported() bool { return true }

// bindWrappingKey mixes fresh random wrapping material with stable machine
// identity and this boot's identity. The random input keeps the result
// ephemeral; machine/boot binding makes copied registry state unusable after
// host migration or reboot.
func bindWrappingKey(key []byte) error {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return err
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("nebula-securekey-host-binding-v1\x00"))
	_, _ = mac.Write(machineID)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(bootID)
	bound := mac.Sum(nil)
	if len(bound) != len(key) {
		return fmt.Errorf("unexpected host-binding length %d", len(bound))
	}
	copy(key, bound)
	wipe(bound)
	return nil
}

func protectMemory(b []byte) error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	// Revoke any ptracer exception inherited from a launcher. CRIU relies on
	// ptrace/process_vm_readv and is denied by the same non-dumpable boundary.
	if err := unix.Prctl(unix.PR_SET_PTRACER, 0, 0, 0, 0); err != nil {
		return err
	}
	if len(b) > 0 {
		pageSize := uintptr(os.Getpagesize())
		address := uintptr(unsafe.Pointer(&b[0]))
		start := address &^ (pageSize - 1)
		end := (address + uintptr(len(b)) + pageSize - 1) &^ (pageSize - 1)
		_, _, errno := unix.Syscall(unix.SYS_MADVISE, start, end-start, unix.MADV_DONTDUMP)
		if errno != 0 {
			return errno
		}
	}
	return unix.Mlock(b)
}

func unprotectMemory(b []byte) {
	_ = unix.Munlock(b)
}
