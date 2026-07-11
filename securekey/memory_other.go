//go:build !linux

package securekey

import "errors"

func Supported() bool { return false }

func protectMemory([]byte) error {
	return errors.New("protected software keys require Linux mlock and PR_SET_DUMPABLE")
}

func unprotectMemory([]byte) {}
