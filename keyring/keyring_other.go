//go:build !linux

package keyring

import "errors"

var errUnsupported = errors.New("Linux kernel keyrings are unsupported on this platform")

func Put(string, []byte) (int, error) { return 0, errUnsupported }
func Consume(string) ([]byte, error)  { return nil, errUnsupported }
