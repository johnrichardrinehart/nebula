package noiseutil

import (
	"crypto/ecdh"
	"strings"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/tpmclient"
)

// DHP256TPM and DHP384TPM use TPM2_ECDH_ZGen when the private key is a tpm2:
// URI. GenerateKeypair and ephemeral handshake operations remain software
// operations; only the configured static private key is TPM-resident.
var (
	DHP256TPM noise.DHFunc = newNISTTPMCurve("P256", ecdh.P256(), 32)
	DHP384TPM noise.DHFunc = newNISTTPMCurve("P384", ecdh.P384(), 48)
)

type nistTPMCurve struct {
	nistCurve
}

func newNISTTPMCurve(name string, curve ecdh.Curve, byteLen int) nistTPMCurve {
	return nistTPMCurve{newNISTCurve(name, curve, byteLen)}
}

func (c nistTPMCurve) DH(privateKey, peerPublic []byte) ([]byte, error) {
	if !strings.HasPrefix(string(privateKey), "tpm2:") {
		return c.nistCurve.DH(privateKey, peerPublic)
	}
	key, err := tpmclient.ParseKeyURI(string(privateKey))
	if err != nil {
		return nil, err
	}
	return key.ECDH(peerPublic)
}
