// Package tpmclient performs ECDH with a non-exportable key in a TPM 2.0.
package tpmclient

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const uriScheme = "tpm2"

// Key identifies a persistent TPM ECDH key. Calls are serialized because most
// kernel TPM resource manager devices and TPM implementations have bounded
// command concurrency.
type Key struct {
	device  string
	handle  tpm2.TPMHandle
	auth    []byte
	curve   ecdh.Curve
	curveID tpm2.TPMECCCurve
	byteLen int

	mu sync.Mutex
}

// ParseKeyURI parses tpm2:device=/dev/tpmrm0;handle=0x81000001;curve=P256.
// auth-env may name an environment variable containing the object auth value;
// embedding authorization secrets in the URI is intentionally unsupported.
func ParseKeyURI(raw string) (*Key, error) {
	if !strings.HasPrefix(raw, uriScheme+":") {
		return nil, errors.New("TPM key URI must start with tpm2:")
	}
	values := make(url.Values)
	for _, item := range strings.Split(strings.TrimPrefix(raw, uriScheme+":"), ";") {
		name, value, ok := strings.Cut(item, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid TPM key URI component %q", item)
		}
		values.Set(name, value)
	}

	device := values.Get("device")
	if device == "" {
		device = "/dev/tpmrm0"
	}
	h, err := strconv.ParseUint(values.Get("handle"), 0, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid TPM persistent handle: %w", err)
	}
	handle := tpm2.TPMHandle(h)
	if handle < 0x81000000 || handle > 0x81ffffff {
		return nil, fmt.Errorf("TPM handle %#x is not persistent", h)
	}

	k := &Key{device: device, handle: handle}
	switch strings.ToUpper(values.Get("curve")) {
	case "P256":
		k.curve, k.curveID, k.byteLen = ecdh.P256(), tpm2.TPMECCNistP256, 32
	case "P384":
		k.curve, k.curveID, k.byteLen = ecdh.P384(), tpm2.TPMECCNistP384, 48
	default:
		return nil, fmt.Errorf("unsupported TPM ECDH curve %q", values.Get("curve"))
	}

	if env := values.Get("auth-env"); env != "" {
		auth, ok := os.LookupEnv(env)
		if !ok {
			return nil, fmt.Errorf("TPM auth environment variable %q is unset", env)
		}
		k.auth = []byte(auth)
	}
	return k, nil
}

// CurveName returns the configured and subsequently TPM-verified curve name.
func (k *Key) CurveName() string {
	if k.curveID == tpm2.TPMECCNistP384 {
		return "P384"
	}
	return "P256"
}

// PublicKey reads and validates the persistent object's public area.
func (k *Key) PublicKey() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	t, err := transport.OpenTPM(k.device)
	if err != nil {
		return nil, fmt.Errorf("open TPM %s: %w", k.device, err)
	}
	defer t.Close()

	pub, _, err := k.readPublic(t)
	if err != nil {
		return nil, err
	}
	return pub.Bytes(), nil
}

// ECDH validates peerPublic and asks the TPM to multiply it by the persistent
// private scalar. Only the shared X coordinate leaves the TPM.
func (k *Key) ECDH(peerPublic []byte) ([]byte, error) {
	peer, err := k.curve.NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public point: %w", err)
	}
	x, y, err := tpm2.ECCPoint(peer)
	if err != nil {
		return nil, fmt.Errorf("decode peer public point: %w", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	t, err := transport.OpenTPM(k.device)
	if err != nil {
		return nil, fmt.Errorf("open TPM %s: %w", k.device, err)
	}
	defer t.Close()

	_, name, err := k.readPublic(t)
	if err != nil {
		return nil, err
	}
	rsp, err := (tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   name,
			Auth:   tpm2.PasswordAuth(k.auth),
		},
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, k.byteLen))},
			Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, k.byteLen))},
		}),
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("TPM ECDH_ZGen: %w", err)
	}
	point, err := rsp.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("decode TPM ECDH result: %w", err)
	}
	if len(point.X.Buffer) > k.byteLen {
		return nil, errors.New("TPM returned oversized ECDH coordinate")
	}
	secret := make([]byte, k.byteLen)
	copy(secret[k.byteLen-len(point.X.Buffer):], point.X.Buffer)
	return secret, nil
}

func (k *Key) readPublic(t transport.TPM) (*ecdh.PublicKey, tpm2.TPM2BName, error) {
	rsp, err := (tpm2.ReadPublic{ObjectHandle: k.handle}).Execute(t)
	if err != nil {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("read TPM public handle %#x: %w", k.handle, err)
	}
	contents, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("decode TPM public area: %w", err)
	}
	if contents.Type != tpm2.TPMAlgECC {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("TPM handle %#x is not an ECC key", k.handle)
	}
	attrs := contents.ObjectAttributes
	if !attrs.FixedTPM || !attrs.FixedParent || !attrs.SensitiveDataOrigin || !attrs.Decrypt || attrs.Restricted {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("TPM handle %#x does not have required non-exportable ECDH attributes", k.handle)
	}
	params, err := contents.Parameters.ECCDetail()
	if err != nil {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("decode TPM ECC parameters: %w", err)
	}
	if params.CurveID != k.curveID {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("TPM key curve %v does not match configured curve %v", params.CurveID, k.curveID)
	}
	if params.Scheme.Scheme != tpm2.TPMAlgECDH && params.Scheme.Scheme != tpm2.TPMAlgNull {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("TPM key scheme %v is not ECDH", params.Scheme.Scheme)
	}
	point, err := contents.Unique.ECC()
	if err != nil {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("decode TPM ECC point: %w", err)
	}
	encoded := make([]byte, 1+2*k.byteLen)
	encoded[0] = 4
	copy(encoded[1+k.byteLen-len(point.X.Buffer):1+k.byteLen], point.X.Buffer)
	copy(encoded[1+2*k.byteLen-len(point.Y.Buffer):], point.Y.Buffer)
	pub, err := k.curve.NewPublicKey(encoded)
	if err != nil {
		return nil, tpm2.TPM2BName{}, fmt.Errorf("invalid TPM public point %s: %w", hex.EncodeToString(encoded), err)
	}
	return pub, rsp.Name, nil
}

// PointFromCoordinates exists for tests that need canonical uncompressed
// encoding without relying on elliptic.Curve's deprecated APIs.
func PointFromCoordinates(byteLen int, x, y *big.Int) []byte {
	out := make([]byte, 1+2*byteLen)
	out[0] = 4
	x.FillBytes(out[1 : 1+byteLen])
	y.FillBytes(out[1+byteLen:])
	return out
}
