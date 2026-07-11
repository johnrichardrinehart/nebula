package cert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestP384CertificateRoundTrip(t *testing.T) {
	for _, version := range []Version{Version1, Version2} {
		t.Run(versionString(version), func(t *testing.T) {
			ca, caPublic, caPrivate, _ := NewTestCaCert(version, Curve_P384, time.Time{}, time.Time{}, nil, nil, nil)
			leaf, public, privatePEM, certificatePEM := NewTestCert(version, Curve_P384, ca, caPrivate, "p384", time.Time{}, time.Time{}, nil, nil, nil)

			assert.True(t, leaf.CheckSignature(caPublic))
			private, rest, curve, err := UnmarshalPrivateKeyFromPEM(privatePEM)
			require.NoError(t, err)
			assert.Empty(t, rest)
			assert.Equal(t, Curve_P384, curve)
			require.NoError(t, leaf.VerifyPrivateKey(curve, private))
			assert.Equal(t, public, leaf.PublicKey())

			roundTripped, rest, err := UnmarshalCertificateFromPEM(certificatePEM)
			require.NoError(t, err)
			assert.Empty(t, rest)
			assert.Equal(t, Curve_P384, roundTripped.Curve())
			assert.True(t, roundTripped.CheckSignature(caPublic))
		})
	}
}

func versionString(v Version) string {
	if v == Version1 {
		return "v1"
	}
	return "v2"
}
