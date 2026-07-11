package securekey

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectEncryptsAndWipesSoftwareKey(t *testing.T) {
	plaintext := []byte("0123456789abcdef0123456789abcdef")
	want := append([]byte(nil), plaintext...)
	reference, err := Protect(plaintext)
	require.NoError(t, err)
	t.Cleanup(func() { _ = Destroy(reference) })
	assert.Equal(t, make([]byte, len(plaintext)), plaintext)
	assert.NotContains(t, string(reference), string(want))

	id := string(reference[len(referencePrefix):])
	value, ok := registry.Load(id)
	require.True(t, ok)
	e := value.(*entry)
	assert.False(t, bytes.Contains(e.ciphertext, want))
	assert.NotEqual(t, want, e.wrappingKey)

	got, err := WithPlaintext(reference, func(key []byte) ([]byte, error) {
		assert.Equal(t, want, key)
		return append([]byte(nil), key...), nil
	})
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestDestroyInvalidatesReference(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	reference, err := Protect(key)
	require.NoError(t, err)
	require.NoError(t, Destroy(reference))
	_, err = WithPlaintext(reference, func(key []byte) ([]byte, error) { return key, nil })
	assert.ErrorContains(t, err, "unavailable")
}
