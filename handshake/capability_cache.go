package handshake

import (
	"errors"
	"sync"
	"time"
)

var ErrCapabilityDowngrade = errors.New("peer previously advertised mixed-curve capabilities")

type capabilityObservation struct {
	expires time.Time
}

// CapabilityCache remembers authenticated capable peers until their bootstrap
// certificate expires. It prevents a later capability-free connection from
// being silently reclassified as a stock peer.
type CapabilityCache struct {
	mu      sync.Mutex
	capable map[string]capabilityObservation
}

func NewCapabilityCache() *CapabilityCache {
	return &CapabilityCache{capable: make(map[string]capabilityObservation)}
}

// Observe records an authenticated result or rejects capability stripping.
// allowFallback is an explicit administrative override, never an automatic
// timeout/error fallback.
func (c *CapabilityCache) Observe(fingerprint string, expires time.Time, advertised, allowFallback bool, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, observation := range c.capable {
		if !now.Before(observation.expires) {
			delete(c.capable, key)
		}
	}
	if advertised {
		c.capable[fingerprint] = capabilityObservation{expires: expires}
		return nil
	}
	if _, known := c.capable[fingerprint]; known && !allowFallback {
		return ErrCapabilityDowngrade
	}
	return nil
}

func (c *CapabilityCache) Clear(fingerprint string) {
	c.mu.Lock()
	delete(c.capable, fingerprint)
	c.mu.Unlock()
}
