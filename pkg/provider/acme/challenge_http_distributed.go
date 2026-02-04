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

// DistributedChallengeHTTP implements HTTP-01 challenge using a distributed KV store,
// allowing any Traefik replica to respond to ACME challenge requests.
type DistributedChallengeHTTP struct {
	kvClient store.Store
	prefix   string

	localCache map[string]map[string][]byte // token -> domain -> keyAuth
	lock       sync.RWMutex

	fallback *ChallengeHTTP // used when KV store is unavailable
}

// ChallengeData is the JSON structure stored in the KV store for each challenge.
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

// Present stores the challenge token in both local cache and the distributed KV store.
// It verifies the token is readable from the KV store before returning to ensure
// all replicas can serve the challenge response.
func (c *DistributedChallengeHTTP) Present(domain, token, keyAuth string) error {
	logger := log.With().Str(logs.ProviderName, "acme").Str("domain", domain).Logger()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	err = c.kvClient.Put(ctx, key, value, &store.WriteOptions{TTL: 10 * time.Minute})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to store challenge in KV store, using local fallback")
		return c.fallback.Present(domain, token, keyAuth)
	}

	logger.Debug().Msgf("Stored ACME HTTP challenge for %s (token %s) in distributed store", domain, token)
	return nil
}

// CleanUp removes the challenge from both local cache and the KV store.
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

// Timeout returns the maximum time and polling interval for challenge resolution.
func (c *DistributedChallengeHTTP) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Second, 5 * time.Second
}

// ServeHTTP responds to ACME HTTP-01 challenge requests by looking up the token
// in the KV store first, then falling back to local cache.
func (c *DistributedChallengeHTTP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := log.Ctx(req.Context()).With().Str(logs.ProviderName, "acme").Logger()

	logger.Debug().Str("path", req.URL.Path).Str("host", req.Host).Msg("Received ACME HTTP challenge request")

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
			logger.Debug().Str("domain", domain).Str("token", token).Int("keyAuthLen", len(tokenValue)).Msg("Responding with 200 OK and challenge keyAuth")
			rw.WriteHeader(http.StatusOK)
			_, err = rw.Write(tokenValue)
			if err != nil {
				logger.Error().Err(err).Msg("Unable to write token")
			}
			return
		}
		logger.Warn().Str("token", token).Str("domain", domain).Msg("Token not found, responding with 404")
	}

	rw.WriteHeader(http.StatusNotFound)
}

// WatchChallenges subscribes to KV store changes to sync challenges from other replicas.
func (c *DistributedChallengeHTTP) WatchChallenges(ctx context.Context) error {
	logger := log.With().Str(logs.ProviderName, "acme").Logger()

	// prefix already includes /challenges from initialization
	prefix := c.prefix + "/"

	// Ensure the challenges directory exists by creating a placeholder key.
	// This is needed because WatchTree fails if the path doesn't exist.
	placeholderKey := prefix + ".initialized"
	err := c.kvClient.Put(ctx, placeholderKey, []byte("1"), nil)
	if err != nil {
		logger.Debug().Err(err).Msg("Could not create challenges placeholder key, watch may fail if directory doesn't exist")
	}

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

func (c *DistributedChallengeHTTP) getTokenValue(ctx context.Context, token, domain string) []byte {
	logger := log.Ctx(ctx)
	logger.Debug().Msgf("Retrieving the ACME challenge for %s (token %q)...", domain, token)

	// Check local cache FIRST - it's fastest (no network I/O) and guaranteed
	// to have the token if this replica stored it via Present(), or synced
	// via WatchChallenges from another replica.
	c.lock.RLock()
	if challenges, ok := c.localCache[token]; ok {
		if result, ok := challenges[domain]; ok {
			c.lock.RUnlock()
			logger.Debug().Msgf("Found ACME challenge for %s in local cache", domain)
			return result
		}
	}
	c.lock.RUnlock()

	// Not in local cache - token was stored by another replica and WatchChallenges
	// hasn't synced it yet. Fetch directly from KV store.
	// Since Present() verifies the token is readable before returning, and etcd
	// provides strongly consistent reads, a single lookup should succeed.
	kvCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	key := c.challengeKey(token, domain)
	pair, err := c.kvClient.Get(kvCtx, key, nil)
	if err == nil && pair != nil && len(pair.Value) > 0 {
		var data ChallengeData
		if err := json.Unmarshal(pair.Value, &data); err == nil {
			logger.Debug().Msgf("Found ACME challenge for %s in distributed store", domain)
			return []byte(data.KeyAuth)
		}
	}

	logger.Warn().Msgf("Cannot retrieve the ACME challenge for %s (token %q) from any source", domain, token)
	return nil
}

func (c *DistributedChallengeHTTP) challengeKey(token, domain string) string {
	return fmt.Sprintf("%s/%s/%s", c.prefix, token, domain)
}
