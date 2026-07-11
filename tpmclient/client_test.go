package tpmclient

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyURI(t *testing.T) {
	t.Setenv("NEBULA_TPM_AUTH", "secret")
	k, err := ParseKeyURI("tpm2:device=/tmp/tpm;handle=0x81000042;curve=P384;auth-env=NEBULA_TPM_AUTH")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/tpm", k.device)
	assert.Equal(t, 48, k.byteLen)
	assert.Equal(t, []byte("secret"), k.auth)
}

func TestParseKeyURIRejectsInvalidValues(t *testing.T) {
	for _, uri := range []string{
		"file:/dev/tpmrm0",
		"tpm2:handle=garbage;curve=P256",
		"tpm2:handle=0x80000000;curve=P256",
		"tpm2:handle=0x81000001;curve=X25519",
		"tpm2:handle=0x81000001;curve=P256;auth-env=MISSING_AUTH",
	} {
		t.Run(uri, func(t *testing.T) {
			_, err := ParseKeyURI(uri)
			assert.Error(t, err)
		})
	}
}

func TestECDHRejectsInvalidPointBeforeOpeningTPM(t *testing.T) {
	k, err := ParseKeyURI("tpm2:device=/does/not/exist;handle=0x81000001;curve=P256")
	require.NoError(t, err)
	_, err = k.ECDH([]byte("not a point"))
	assert.ErrorContains(t, err, "invalid peer public point")
	assert.NotErrorIs(t, err, nil)
}

func TestPointFromCoordinates(t *testing.T) {
	got := PointFromCoordinates(2, big.NewInt(1), big.NewInt(2))
	assert.Equal(t, []byte{4, 0, 1, 0, 2}, got)
}
