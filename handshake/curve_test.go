package handshake

import (
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectCurveUsesInitiatorPreference(t *testing.T) {
	selected, err := SelectCurve(
		[]cert.Curve{cert.Curve_P384, cert.Curve_P256, cert.Curve_CURVE25519},
		[]cert.Curve{cert.Curve_P256, cert.Curve_P384, cert.Curve_CURVE25519},
	)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_P384, selected)
}

func TestSelectCurveFindsLowerMutualPreference(t *testing.T) {
	selected, err := SelectCurve(
		[]cert.Curve{cert.Curve_P384, cert.Curve_CURVE25519},
		[]cert.Curve{cert.Curve_P256, cert.Curve_CURVE25519},
	)
	require.NoError(t, err)
	assert.Equal(t, cert.Curve_CURVE25519, selected)
}

func TestSelectCurveRejectsAmbiguousLists(t *testing.T) {
	tests := []struct {
		name      string
		initiator []cert.Curve
		responder []cert.Curve
	}{
		{"empty", nil, []cert.Curve{cert.Curve_P256}},
		{"duplicate", []cert.Curve{cert.Curve_P256, cert.Curve_P256}, []cert.Curve{cert.Curve_P256}},
		{"unknown", []cert.Curve{cert.Curve(99)}, []cert.Curve{cert.Curve_P256}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SelectCurve(tt.initiator, tt.responder)
			assert.Error(t, err)
		})
	}
}

func TestSelectCurveNoIntersection(t *testing.T) {
	_, err := SelectCurve([]cert.Curve{cert.Curve_P384}, []cert.Curve{cert.Curve_P256})
	assert.ErrorIs(t, err, ErrNoMutuallySupportedCurve)
}
