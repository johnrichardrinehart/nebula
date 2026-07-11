package handshake

import (
	"errors"
	"fmt"

	"github.com/slackhq/nebula/cert"
)

var ErrNoMutuallySupportedCurve = errors.New("no mutually supported curve")

const maxCurvePreferences = 3

// SelectCurve returns the first initiator preference supported by the
// responder. Inputs are rejected rather than normalized so duplicates and
// unknown values cannot create transcript ambiguities.
func SelectCurve(initiatorPreferences, responderSupported []cert.Curve) (cert.Curve, error) {
	if err := validateCurveList("initiator", initiatorPreferences); err != nil {
		return 0, err
	}
	if err := validateCurveList("responder", responderSupported); err != nil {
		return 0, err
	}

	available := make(map[cert.Curve]struct{}, len(responderSupported))
	for _, curve := range responderSupported {
		available[curve] = struct{}{}
	}
	for _, curve := range initiatorPreferences {
		if _, ok := available[curve]; ok {
			return curve, nil
		}
	}
	return 0, ErrNoMutuallySupportedCurve
}

func validateCurveList(peer string, curves []cert.Curve) error {
	if len(curves) == 0 || len(curves) > maxCurvePreferences {
		return fmt.Errorf("%s curve list length %d is invalid", peer, len(curves))
	}
	seen := make(map[cert.Curve]struct{}, len(curves))
	for _, curve := range curves {
		switch curve {
		case cert.Curve_CURVE25519, cert.Curve_P256, cert.Curve_P384:
		default:
			return fmt.Errorf("%s advertised unknown curve %d", peer, curve)
		}
		if _, ok := seen[curve]; ok {
			return fmt.Errorf("%s advertised duplicate curve %s", peer, curve)
		}
		seen[curve] = struct{}{}
	}
	return nil
}
