package handshake

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCapabilityCacheRejectsStripping(t *testing.T) {
	now := time.Now()
	cache := NewCapabilityCache()
	require.NoError(t, cache.Observe("peer", now.Add(time.Hour), true, false, now))
	require.ErrorIs(t, cache.Observe("peer", now.Add(time.Hour), false, false, now), ErrCapabilityDowngrade)
	require.NoError(t, cache.Observe("peer", now.Add(time.Hour), false, true, now))
}

func TestCapabilityCachePersistsAcrossRestart(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "capabilities.json")
	cache := NewCapabilityCache(path)
	require.NoError(t, cache.Observe("peer", now.Add(time.Hour), true, false, now))

	restarted := NewCapabilityCache(path)
	require.ErrorIs(t, restarted.Observe("peer", now.Add(time.Hour), false, false, now), ErrCapabilityDowngrade)
	require.NoError(t, restarted.Observe("peer", now.Add(time.Hour), false, true, now))
}

func TestCapabilityCacheExpiresAndClears(t *testing.T) {
	now := time.Now()
	cache := NewCapabilityCache()
	require.NoError(t, cache.Observe("peer", now.Add(time.Minute), true, false, now))
	require.NoError(t, cache.Observe("peer", now.Add(time.Hour), false, false, now.Add(2*time.Minute)))
	require.NoError(t, cache.Observe("peer", now.Add(time.Hour), true, false, now))
	cache.Clear("peer")
	require.False(t, errors.Is(cache.Observe("peer", now.Add(time.Hour), false, false, now), ErrCapabilityDowngrade))
}
