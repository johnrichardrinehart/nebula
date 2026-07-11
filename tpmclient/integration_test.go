package tpmclient

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPersistentTPMECDH(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		curve ecdh.Curve
	}{
		{"P256", "NEBULA_TEST_TPM_URI_P256", ecdh.P256()},
		{"P384", "NEBULA_TEST_TPM_URI_P384", ecdh.P384()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := os.Getenv(tt.env)
			if uri == "" {
				t.Skipf("%s is not set", tt.env)
			}
			key, err := ParseKeyURI(uri)
			require.NoError(t, err)
			publicBytes, err := key.PublicKey()
			require.NoError(t, err)
			public, err := tt.curve.NewPublicKey(publicBytes)
			require.NoError(t, err)

			peer, err := tt.curve.GenerateKey(rand.Reader)
			require.NoError(t, err)
			want, err := peer.ECDH(public)
			require.NoError(t, err)
			got, err := key.ECDH(peer.PublicKey().Bytes())
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}
