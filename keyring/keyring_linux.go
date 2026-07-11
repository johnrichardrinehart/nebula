//go:build linux

// Package keyring transfers private-key material through a Linux service
// session keyring without creating a plaintext file.
package keyring

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const possessorOnlyPermissions uint32 = 0x3f000000

// Put adds a user key to the current session keyring and removes all
// user/group/other permissions. Possessor permissions allow a subsequently
// exec'd service process to consume it.
func Put(description string, payload []byte) (int, error) {
	if description == "" || len(payload) == 0 {
		return 0, errors.New("key description and payload are required")
	}
	id, err := unix.AddKey("user", description, payload, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		return 0, fmt.Errorf("add key to session keyring: %w", err)
	}
	if err := unix.KeyctlSetperm(id, possessorOnlyPermissions); err != nil {
		_, _ = unix.KeyctlInt(unix.KEYCTL_REVOKE, id, 0, 0, 0)
		return 0, fmt.Errorf("restrict key permissions: %w", err)
	}
	return id, nil
}

// Consume reads and immediately revokes a user key from the current session
// keyring. The caller owns and must wipe the returned bytes.
func Consume(description string) ([]byte, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, "user", description, 0)
	if err != nil {
		return nil, fmt.Errorf("find key %q in session keyring: %w", description, err)
	}
	defer func() { _, _ = unix.KeyctlInt(unix.KEYCTL_REVOKE, id, 0, 0, 0) }()

	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("measure keyring payload: %w", err)
	}
	payload := make([]byte, size)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, payload, 0)
	if err != nil {
		return nil, fmt.Errorf("read keyring payload: %w", err)
	}
	return payload[:n], nil
}
