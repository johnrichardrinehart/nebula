package handshake

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/tpmclient"
	"github.com/stretchr/testify/require"
)

func TestTPMBackedUpgradeHandshake(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		curve     cert.Curve
		dh        noise.DHFunc
		subtype   header.MessageSubType
	}{
		{"p256", "NEBULA_TEST_TPM_URI_P256", cert.Curve_P256, noiseutil.DHP256TPM, header.HandshakeIXP256Upgrade},
		{"p384", "NEBULA_TEST_TPM_URI_P384", cert.Curve_P384, noiseutil.DHP384TPM, header.HandshakeIXP384Upgrade},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uri := os.Getenv(tc.env)
			if uri == "" {
				t.Skip("TPM integration URI is not configured")
			}
			key, err := tpmclient.ParseKeyURI(uri)
			require.NoError(t, err)
			public, err := key.PublicKey()
			require.NoError(t, err)

			now := time.Now().Truncate(time.Second)
			ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, tc.curve, now, now.Add(time.Hour), nil, nil, nil)
			pool := cert.NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			network := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
			leaf, err := (&cert.TBSCertificate{Version: cert.Version2, Curve: tc.curve, Name: "tpm", Networks: network, NotBefore: now, NotAfter: now.Add(time.Hour), PublicKey: public}).Sign(ca, tc.curve, caKey)
			require.NoError(t, err)
			encoded, err := leaf.MarshalForHandshakes()
			require.NoError(t, err)
			tpmState := &testCertState{version: cert.Version2, creds: map[cert.Version]*Credential{cert.Version2: NewCredential(leaf, encoded, []byte(uri), noise.NewCipherSuite(tc.dh, noise.CipherChaChaPoly, noise.HashSHA256))}}

			softwareDH := noiseutil.DHP256
			if tc.curve == cert.Curve_P384 {
				softwareDH = noiseutil.DHP384
			}
			software := newCurveTestState(t, ca, caKey, tc.curve, softwareDH, "software", "10.0.0.2/24")
			prologue := make([]byte, 32)
			prologue[0] = 1
			verifier := testVerifier(pool)
			init, err := NewMachineWithPrologue(cert.Version2, tpmState.getCredential, verifier, func() (uint32, error) { return 1, nil }, true, tc.subtype, prologue)
			require.NoError(t, err)
			resp, err := NewMachineWithPrologue(cert.Version2, software.getCredential, verifier, func() (uint32, error) { return 2, nil }, false, tc.subtype, prologue)
			require.NoError(t, err)
			msg1, err := init.Initiate(nil)
			require.NoError(t, err)
			msg2, _, err := resp.ProcessPacket(nil, msg1)
			require.NoError(t, err)
			_, result, err := init.ProcessPacket(nil, msg2)
			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}
