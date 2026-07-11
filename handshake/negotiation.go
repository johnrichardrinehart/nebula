package handshake

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/slackhq/nebula/cert"
)

const negotiationDomain = "nebula-mixed-curve-upgrade-v1"

type UpgradePlan struct {
	Curve    cert.Curve
	Prologue [sha256.Size]byte
}

// PlanUpgrade deterministically derives the upgrade selected by the
// initiator's authenticated preference order. A stock peer yields
// ErrNoMutuallySupportedCurve rather than an implicit downgrade decision.
func PlanUpgrade(result *Result) (UpgradePlan, error) {
	if result == nil || result.MyCert == nil || result.RemoteCert == nil {
		return UpgradePlan{}, fmt.Errorf("bootstrap handshake result is incomplete")
	}
	var initiator, responder Payload
	if result.Initiator {
		initiator = Payload{KeyCapabilities: result.LocalCapabilities, CapabilityNonce: result.LocalCapabilityNonce}
		responder = Payload{KeyCapabilities: result.RemoteCapabilities, CapabilityNonce: result.RemoteCapabilityNonce}
	} else {
		initiator = Payload{KeyCapabilities: result.RemoteCapabilities, CapabilityNonce: result.RemoteCapabilityNonce}
		responder = Payload{KeyCapabilities: result.LocalCapabilities, CapabilityNonce: result.LocalCapabilityNonce}
	}
	initiatorCurves, err := capabilityCurves(initiator.KeyCapabilities)
	if err != nil {
		return UpgradePlan{}, err
	}
	responderCurves, err := capabilityCurves(responder.KeyCapabilities)
	if err != nil {
		return UpgradePlan{}, err
	}
	selected, err := SelectCurve(initiatorCurves, responderCurves)
	if err != nil {
		return UpgradePlan{}, err
	}
	myFingerprint, err := result.MyCert.Fingerprint()
	if err != nil {
		return UpgradePlan{}, err
	}
	remoteFingerprint := result.RemoteCert.Fingerprint
	initFingerprint, respFingerprint := []byte(myFingerprint), []byte(remoteFingerprint)
	if !result.Initiator {
		initFingerprint, respFingerprint = respFingerprint, initFingerprint
	}
	prologue, err := NegotiationTranscript(initiator, responder, selected, initFingerprint, respFingerprint)
	if err != nil {
		return UpgradePlan{}, err
	}
	return UpgradePlan{Curve: selected, Prologue: prologue}, nil
}

// ValidateCapabilities validates every advertised certificate and enforces
// that it represents the same Nebula identity as the authenticated bootstrap.
func ValidateCapabilities(payload Payload, bootstrap cert.Certificate, verifier CertVerifier) (map[cert.Curve]cert.Certificate, error) {
	if len(payload.KeyCapabilities) == 0 || len(payload.CapabilityNonce) != 32 {
		return nil, fmt.Errorf("incomplete capability advertisement")
	}
	curves, err := capabilityCurves(payload.KeyCapabilities)
	if err != nil {
		return nil, err
	}
	validated := make(map[cert.Curve]cert.Certificate, len(curves))
	for i, advertised := range payload.KeyCapabilities {
		c, rest, err := cert.UnmarshalCertificateFromPEM(advertised.Certificate)
		if err != nil {
			return nil, fmt.Errorf("decode capability %d: %w", i, err)
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("decode capability %d: trailing certificate data", i)
		}
		curve := curves[i]
		if c.Curve() != curve {
			return nil, fmt.Errorf("capability %d curve mismatch", i)
		}
		if c.Name() != bootstrap.Name() ||
			!slices.Equal(c.Networks(), bootstrap.Networks()) ||
			!slices.Equal(c.UnsafeNetworks(), bootstrap.UnsafeNetworks()) ||
			!slices.Equal(c.Groups(), bootstrap.Groups()) ||
			!c.NotBefore().Equal(bootstrap.NotBefore()) || !c.NotAfter().Equal(bootstrap.NotAfter()) {
			return nil, fmt.Errorf("capability %d identity does not match bootstrap", i)
		}
		if _, err := verifier(c); err != nil {
			return nil, fmt.Errorf("verify capability %d: %w", i, err)
		}
		validated[curve] = c
	}
	return validated, nil
}

// NegotiationTranscript binds both authenticated advertisements to one
// selected curve and bootstrap connection. The result is suitable as a Noise
// prologue for the explicit upgrade handshake.
func NegotiationTranscript(
	initiator, responder Payload,
	selected cert.Curve,
	initiatorBootstrap, responderBootstrap []byte,
) ([sha256.Size]byte, error) {
	if len(initiator.CapabilityNonce) != 32 || len(responder.CapabilityNonce) != 32 {
		return [sha256.Size]byte{}, fmt.Errorf("capability nonces must be 32 bytes")
	}
	initiatorCurves, err := capabilityCurves(initiator.KeyCapabilities)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	responderCurves, err := capabilityCurves(responder.KeyCapabilities)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	got, err := SelectCurve(initiatorCurves, responderCurves)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if got != selected {
		return [sha256.Size]byte{}, fmt.Errorf("selected curve %s does not match negotiated curve %s", selected, got)
	}

	h := sha256.New()
	writeTranscriptField(h, []byte(negotiationDomain))
	writeTranscriptField(h, []byte("initiator"))
	writeTranscriptField(h, canonicalCapabilities(initiator.KeyCapabilities))
	writeTranscriptField(h, initiator.CapabilityNonce)
	writeTranscriptField(h, initiatorBootstrap)
	writeTranscriptField(h, []byte("responder"))
	writeTranscriptField(h, canonicalCapabilities(responder.KeyCapabilities))
	writeTranscriptField(h, responder.CapabilityNonce)
	writeTranscriptField(h, responderBootstrap)
	var curve [4]byte
	binary.BigEndian.PutUint32(curve[:], uint32(selected))
	writeTranscriptField(h, curve[:])

	var transcript [sha256.Size]byte
	copy(transcript[:], h.Sum(nil))
	return transcript, nil
}

func capabilityCurves(capabilities []KeyCapability) ([]cert.Curve, error) {
	curves := make([]cert.Curve, len(capabilities))
	for i, capability := range capabilities {
		curves[i] = cert.Curve(capability.Curve)
	}
	if err := validateCurveList("capability", curves); err != nil {
		return nil, err
	}
	return curves, nil
}

func canonicalCapabilities(capabilities []KeyCapability) []byte {
	var out []byte
	for _, capability := range capabilities {
		var curve [4]byte
		binary.BigEndian.PutUint32(curve[:], capability.Curve)
		out = append(out, curve[:]...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(capability.Certificate)))
		out = append(out, capability.Certificate...)
	}
	return out
}

func writeTranscriptField(h interface{ Write([]byte) (int, error) }, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(value)
}
