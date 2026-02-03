package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kvtools/valkeyrie/store"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
)

// DistributedChallengeHTTP implements the HTTP-01 challenge with distributed storage.
// This allows multiple Traefik replicas to share challenge tokens, enabling
// any replica to respond to ACME challenge requests.
type DistributedChallengeHTTP struct {
	kvClient store.Store
	prefix   string

	// Local cache for faster lookups
	localCache map[string]map[string][]byte
	lock       sync.RWMutex

	// Fallback to local storage if KV store is unavailable
	fallback *ChallengeHTTP
}

// ChallengeData represents a challenge token stored in the KV store.
type ChallengeData struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

// NewDistributedChallengeHTTP creates a new distributed HTTP challenge provider.
func NewDistributedChallengeHTTP(kvClient store.Store, prefix string) *DistributedChallengeHTTP {
	return &DistributedChallengeHTTP{
		kvClient:   kvClient,
		prefix:     prefix,
		localCache: make(map[string]map[string][]byte),
		fallback:   NewChallengeHTTP(),
	}
}

// Present presents a challenge to obtain new ACME certificate.
// The challenge token is stored in the distributed KV store so any replica can respond.
func (c *DistributedChallengeHTTP) Present(domain, token, keyAuth string) error {
	logger := log.With().Str(logs.ProviderName, "acme").Str("domain", domain).Logger()
	ctx := context.Background()

	// Store in local cache first
	c.lock.Lock()
	if _, ok := c.localCache[token]; !ok {
		c.localCache[token] = map[string][]byte{}
	}
	c.localCache[token][domain] = []byte(keyAuth)
	c.lock.Unlock()

	// Store in distributed KV store
	key := c.challengeKey(token, domain)
	data := ChallengeData{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
	}

	value, err := json.Marshal(data)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal challenge data")
		return c.fallback.Present(domain, token, keyAuth)
	}

	// Store with TTL of 10 minutes (challenges should complete quickly)
	err = c.kvClient.Put(ctx, key, value, &store.WriteOptions{TTL: 10 * time.Minute})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to store challenge in KV store, using local fallback")
		return c.fallback.Present(domain, token, keyAuth)
	}

	logger.Debug().Msgf("Stored ACME HTTP challenge for %s (token %s) in distributed store", domain, token)
	return nil
}

// CleanUp cleans the challenges when certificate is obtained.
func (c *DistributedChallengeHTTP) CleanUp(domain, token, keyAuth string) error {
	logger := log.With().Str(logs.ProviderName, "acme").Str("domain", domain).Logger()
	ctx := context.Background()

	// Clean local cache
	c.lock.Lock()
	if _, ok := c.localCache[token]; ok {
		delete(c.localCache[token], domain)
		if len(c.localCache[token]) == 0 {
			delete(c.localCache, token)
		}
	}
	c.lock.Unlock()

	// Clean from KV store
	key := c.challengeKey(token, domain)
	err := c.kvClient.Delete(ctx, key)
	if err != nil && !errors.Is(err, store.ErrKeyNotFound) {
		logger.Warn().Err(err).Msg("Failed to delete challenge from KV store")
	}

	// Also clean fallback
	return c.fallback.CleanUp(domain, token, keyAuth)
}

// Timeout calculates the maximum of time allowed to resolve an ACME challenge.
func (c *DistributedChallengeHTTP) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Second, 5 * time.Second
}

// ServeHTTP handles incoming ACME challenge requests.
// It first checks the distributed KV store, then falls back to local cache.
func (c *DistributedChallengeHTTP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := log.Ctx(req.Context()).With().Str(logs.ProviderName, "acme").Logger()

	token, err := getPathParam(req.URL)
	if err != nil {
		logger.Error().Err(err).Msg("Unable to get token")
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	if token != "" {
		domain, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			logger.Debug().Err(err).Msg("Unable to split host and port. Fallback to request host.")
			domain = req.Host
		}

		tokenValue := c.getTokenValue(logger.WithContext(req.Context()), token, domain)
		if len(tokenValue) > 0 {
			rw.WriteHeader(http.StatusOK)
			_, err = rw.Write(tokenValue)
			if err != nil {
				logger.Error().Err(err).Msg("Unable to write token")
			}
			return
		}
	}

	rw.WriteHeader(http.StatusNotFound)
}

func (c *DistributedChallengeHTTP) getTokenValue(ctx context.Context, token, domain string) []byte {
	logger := log.Ctx(ctx)
	logger.Debug().Msgf("Retrieving the ACME challenge for %s (token %q)...", domain, token)

	// First, try to get from distributed KV store
	key := c.challengeKey(token, domain)
	pair, err := c.kvClient.Get(ctx, key, nil)
	if err == nil && pair != nil && len(pair.Value) > 0 {
		var data ChallengeData
		if err := json.Unmarshal(pair.Value, &data); err == nil {
			logger.Debug().Msgf("Found ACME challenge for %s in distributed store", domain)
			return []byte(data.KeyAuth)
		}
	}

	// Try to find by listing all challenges for this token (in case domain matching is complex)
	tokenPrefix := fmt.Sprintf("%s/%s/", c.prefix, token)
	pairs, err := c.kvClient.List(ctx, tokenPrefix, nil)
	if err == nil {
		for _, p := range pairs {
			var data ChallengeData
			if err := json.Unmarshal(p.Value, &data); err == nil {
				// Check if this challenge matches our domain
				if data.Domain == domain {
					logger.Debug().Msgf("Found ACME challenge for %s in distributed store (via list)", domain)
					return []byte(data.KeyAuth)
				}
			}
		}
	}

	// Fall back to local cache
	c.lock.RLock()
	defer c.lock.RUnlock()

	if challenges, ok := c.localCache[token]; ok {
		if result, ok := challenges[domain]; ok {
			logger.Debug().Msgf("Found ACME challenge for %s in local cache", domain)
			return result
		}
	}

	logger.Warn().Msgf("Cannot retrieve the ACME challenge for %s (token %q) from any source", domain, token)
	return nil
}

func (c *DistributedChallengeHTTP) challengeKey(token, domain string) string {
	return fmt.Sprintf("%s/%s/%s", c.prefix, token, domain)
}

// WatchChallenges watches for new challenges from other replicas.
// This helps pre-populate the local cache for faster response times.
func (c *DistributedChallengeHTTP) WatchChallenges(ctx context.Context) error {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()

	// prefix already includes /challenges from initialization
	prefix := c.prefix + "/"
	events, err := c.kvClient.WatchTree(ctx, prefix, nil)
	if err != nil {
		return fmt.Errorf("failed to watch challenges: %w", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pairs, ok := <-events:
				if !ok {
					logger.Warn().Msg("Challenge watch channel closed")
					return
				}

				// Update local cache with challenges from other replicas
				c.lock.Lock()
				for _, pair := range pairs {
					var data ChallengeData
					if err := json.Unmarshal(pair.Value, &data); err == nil {
						if _, ok := c.localCache[data.Token]; !ok {
							c.localCache[data.Token] = map[string][]byte{}
						}
						c.localCache[data.Token][data.Domain] = []byte(data.KeyAuth)
						logger.Debug().Msgf("Synced ACME challenge for %s from distributed store", data.Domain)
					}
				}
				c.lock.Unlock()
			}
		}
	}()

	return nil
}
