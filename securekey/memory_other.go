//go:build !linux

package securekey

import "errors"

func Supported() bool { return false }

func bindWrappingKey([]byte) error {
	return errors.New("host-bound software keys require Linux machine and boot identity")
}

func protectMemory([]byte) error {
	return errors.New("protected software keys require Linux mlock and PR_SET_DUMPABLE")
}

func unprotectMemory([]byte) {}
