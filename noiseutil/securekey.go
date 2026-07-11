package noiseutil

import (
	"io"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/securekey"
)

// DH25519SecureKey keeps a software X25519 static key encrypted between DH
// calls. Ephemeral Noise keys continue to use the normal software path.
var DH25519SecureKey noise.DHFunc = secureKey25519{}

type secureKey25519 struct{}

func (secureKey25519) GenerateKeypair(rng io.Reader) (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rng)
}

func (secureKey25519) DH(privateKey, publicKey []byte) ([]byte, error) {
	if !securekey.IsReference(privateKey) {
		return noise.DH25519.DH(privateKey, publicKey)
	}
	return securekey.WithPlaintext(privateKey, func(plaintext []byte) ([]byte, error) {
		return noise.DH25519.DH(plaintext, publicKey)
	})
}

func (secureKey25519) DHLen() int     { return noise.DH25519.DHLen() }
func (secureKey25519) DHName() string { return noise.DH25519.DHName() }
