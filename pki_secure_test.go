//go:build linux

package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/securekey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCertStateProtectsSoftwareX25519Key(t *testing.T) {
	ca, _, caPrivate, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	leaf, _, privatePEM, _ := ct.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caPrivate, "protected", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil)
	private, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(privatePEM)
	require.NoError(t, err)
	state, err := newCertState(cert.Version2, nil, leaf, false, curve, private, "aes")
	require.NoError(t, err)
	assert.True(t, securekey.IsReference(state.privateKey))
	assert.Equal(t, make([]byte, len(private)), private)
	_, err = securekey.WithPlaintext(state.privateKey, func(plaintext []byte) ([]byte, error) {
		return nil, leaf.VerifyPrivateKey(curve, plaintext)
	})
	require.NoError(t, err)
}
