package handshake

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrCapabilityDowngrade = errors.New("peer previously advertised mixed-curve capabilities")

type capabilityObservation struct {
	Expires time.Time `json:"expires"`
}

// CapabilityCache remembers authenticated capable peers until their bootstrap
// certificate expires. When path is configured, observations survive daemon
// restarts so restarting cannot erase downgrade history.
type CapabilityCache struct {
	mu      sync.Mutex
	capable map[string]capabilityObservation
	path    string
	loadErr error
}

func NewCapabilityCache(paths ...string) *CapabilityCache {
	c := &CapabilityCache{capable: make(map[string]capabilityObservation)}
	if len(paths) > 0 {
		c.path = paths[0]
		c.loadErr = c.load()
	}
	return c
}

func (c *CapabilityCache) load() error {
	if c.path == "" {
		return nil
	}
	b, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read capability cache: %w", err)
	}
	if err := json.Unmarshal(b, &c.capable); err != nil {
		return fmt.Errorf("parse capability cache: %w", err)
	}
	return nil
}

func (c *CapabilityCache) save() error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c.capable)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Observe records an authenticated result or rejects capability stripping.
func (c *CapabilityCache) Observe(fingerprint string, expires time.Time, advertised, allowFallback bool, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadErr != nil {
		return c.loadErr
	}

	changed := false
	for key, observation := range c.capable {
		if !now.Before(observation.Expires) {
			delete(c.capable, key)
			changed = true
		}
	}
	if advertised {
		c.capable[fingerprint] = capabilityObservation{Expires: expires}
		changed = true
	} else if _, known := c.capable[fingerprint]; known && !allowFallback {
		return ErrCapabilityDowngrade
	}
	if changed {
		return c.save()
	}
	return nil
}

func (c *CapabilityCache) Clear(fingerprint string) {
	c.mu.Lock()
	delete(c.capable, fingerprint)
	_ = c.save()
	c.mu.Unlock()
}
