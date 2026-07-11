package handshake

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/stretchr/testify/require"
)

func TestCapabilityPayloadRoundTrip(t *testing.T) {
	p := Payload{
		Cert: []byte("bootstrap"),
		KeyCapabilities: []KeyCapability{
			{Curve: uint32(cert.Curve_P384), Certificate: []byte("p384-cert")},
			{Curve: uint32(cert.Curve_P256), Certificate: []byte("p256-cert")},
		},
		CapabilityNonce: bytes.Repeat([]byte{7}, 32),
	}
	got, err := UnmarshalPayload(MarshalPayload(nil, p))
	require.NoError(t, err)
	require.Equal(t, p, got)
}

func TestNegotiationTranscriptRejectsReorderAndSubstitution(t *testing.T) {
	init := capabilityPayload(cert.Curve_P384, cert.Curve_P256)
	resp := capabilityPayload(cert.Curve_P256, cert.Curve_P384)
	transcript, err := NegotiationTranscript(init, resp, cert.Curve_P384, []byte("init-x"), []byte("resp-x"))
	require.NoError(t, err)

	reordered := capabilityPayload(cert.Curve_P256, cert.Curve_P384)
	other, err := NegotiationTranscript(reordered, resp, cert.Curve_P256, []byte("init-x"), []byte("resp-x"))
	require.NoError(t, err)
	require.NotEqual(t, transcript, other)

	_, err = NegotiationTranscript(init, resp, cert.Curve_P256, []byte("init-x"), []byte("resp-x"))
	require.ErrorContains(t, err, "does not match")
}

func TestStockCompatibleBootstrapIgnoresForkCapabilities(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	after := now.Add(time.Hour)
	xca, _, xcaKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, now, after, nil, nil, nil)
	pca, _, pcaKey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_P256, now, after, nil, nil, nil)
	pool := cert.NewCAPool()
	require.NoError(t, pool.AddCA(xca))
	require.NoError(t, pool.AddCA(pca))
	networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	fork := newTestCertState(t, xca, xcaKey, "fork", networks)
	upgrade, _, _, upgradePEM := ct.NewTestCert(cert.Version2, cert.Curve_P256, pca, pcaKey, "fork", now, after, networks, nil, nil)
	require.Equal(t, cert.Curve_P256, upgrade.Curve())
	fork.creds[cert.Version2].WithCapabilities([]KeyCapability{{Curve: uint32(cert.Curve_P256), Certificate: upgradePEM}})
	stock := newTestCertState(t, xca, xcaKey, "stock", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	forkResult, stockResult := doFullHandshake(t, fork, stock, pool)
	require.Empty(t, forkResult.RemoteCapabilities)
	require.Len(t, stockResult.RemoteCapabilities, 1)
	require.Equal(t, uint32(cert.Curve_P256), stockResult.RemoteCapabilities[0].Curve)
}

func TestAuthenticatedBootstrapPlansSamePreferredUpgrade(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	after := now.Add(time.Hour)
	xca, _, xkey, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, now, after, nil, nil, nil)
	p256ca, _, p256key, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_P256, now, after, nil, nil, nil)
	p384ca, _, p384key, _ := ct.NewTestCaCert(cert.Version2, cert.Curve_P384, now, after, nil, nil, nil)
	pool := cert.NewCAPool()
	for _, ca := range []cert.Certificate{xca, p256ca, p384ca} {
		require.NoError(t, pool.AddCA(ca))
	}
	makePeer := func(name, network string, preferences []cert.Curve) *testCertState {
		networks := []netip.Prefix{netip.MustParsePrefix(network)}
		state := newTestCertState(t, xca, xkey, name, networks)
		capabilities := make([]KeyCapability, 0, len(preferences))
		for _, curve := range preferences {
			ca, key := p256ca, p256key
			if curve == cert.Curve_P384 {
				ca, key = p384ca, p384key
			}
			_, _, _, pem := ct.NewTestCert(cert.Version2, curve, ca, key, name, now, after, networks, nil, nil)
			capabilities = append(capabilities, KeyCapability{Curve: uint32(curve), Certificate: pem})
		}
		state.creds[cert.Version2].WithCapabilities(capabilities)
		return state
	}
	init := makePeer("init", "10.0.0.1/24", []cert.Curve{cert.Curve_P384, cert.Curve_P256})
	resp := makePeer("resp", "10.0.0.2/24", []cert.Curve{cert.Curve_P256, cert.Curve_P384})
	ir, rr := doFullHandshake(t, init, resp, pool)
	ip, err := PlanUpgrade(ir)
	require.NoError(t, err)
	rp, err := PlanUpgrade(rr)
	require.NoError(t, err)
	require.Equal(t, cert.Curve_P384, ip.Curve)
	require.Equal(t, ip, rp)
}

func TestUpgradeHandshakesP256AndP384(t *testing.T) {
	for _, tc := range []struct {
		name    string
		curve   cert.Curve
		dh      noise.DHFunc
		subtype header.MessageSubType
	}{
		{"p256", cert.Curve_P256, noiseutil.DHP256, header.HandshakeIXP256Upgrade},
		{"p384", cert.Curve_P384, noiseutil.DHP384, header.HandshakeIXP384Upgrade},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, _, caKey, _ := ct.NewTestCaCert(cert.Version2, tc.curve, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)
			pool := cert.NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			init := newCurveTestState(t, ca, caKey, tc.curve, tc.dh, "init", "10.0.0.1/24")
			resp := newCurveTestState(t, ca, caKey, tc.curve, tc.dh, "resp", "10.0.0.2/24")
			prologue := bytes.Repeat([]byte{9}, 32)
			v := testVerifier(pool)
			im, err := NewMachineWithPrologue(cert.Version2, init.getCredential, v, func() (uint32, error) { return 1, nil }, true, tc.subtype, prologue)
			require.NoError(t, err)
			rm, err := NewMachineWithPrologue(cert.Version2, resp.getCredential, v, func() (uint32, error) { return 2, nil }, false, tc.subtype, prologue)
			require.NoError(t, err)
			msg1, err := im.Initiate(nil)
			require.NoError(t, err)
			msg2, rr, err := rm.ProcessPacket(nil, msg1)
			require.NoError(t, err)
			require.NotNil(t, rr)
			_, ir, err := im.ProcessPacket(nil, msg2)
			require.NoError(t, err)
			require.NotNil(t, ir)
		})
	}
}

func capabilityPayload(curves ...cert.Curve) Payload {
	capabilities := make([]KeyCapability, len(curves))
	for i, curve := range curves {
		capabilities[i] = KeyCapability{Curve: uint32(curve), Certificate: []byte{byte(curve), byte(i)}}
	}
	return Payload{KeyCapabilities: capabilities, CapabilityNonce: bytes.Repeat([]byte{byte(len(curves))}, 32)}
}

func newCurveTestState(t *testing.T, ca cert.Certificate, caKey []byte, curve cert.Curve, dh noise.DHFunc, name, network string) *testCertState {
	t.Helper()
	c, _, rawPrivate, _ := ct.NewTestCert(cert.Version2, curve, ca, caKey, name, ca.NotBefore(), ca.NotAfter(), []netip.Prefix{netip.MustParsePrefix(network)}, nil, nil)
	private, _, _, err := cert.UnmarshalPrivateKeyFromPEM(rawPrivate)
	require.NoError(t, err)
	encoded, err := c.MarshalForHandshakes()
	require.NoError(t, err)
	credential := NewCredential(c, encoded, private, noise.NewCipherSuite(dh, noise.CipherChaChaPoly, noise.HashSHA256))
	return &testCertState{version: cert.Version2, creds: map[cert.Version]*Credential{cert.Version2: credential}}
}
