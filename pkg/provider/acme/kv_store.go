package acme

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kvtools/valkeyrie"
	"github.com/kvtools/valkeyrie/store"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/types"
)

// DefaultPrefix is the default KV store prefix for ACME data.
const DefaultPrefix = "traefik/acme"

// Compile-time interface checks to ensure KVStore properly implements both interfaces.
var (
	_ Store            = (*KVStore)(nil)
	_ DistributedStore = (*KVStore)(nil)
)

// KVStoreConfig holds the configuration for connecting to a KV store.
type KVStoreConfig struct {
	// Endpoints is the list of KV store endpoints.
	Endpoints []string `description:"KV store endpoints." json:"endpoints,omitempty" toml:"endpoints,omitempty" yaml:"endpoints,omitempty"`

	// Prefix is the key prefix used for storing ACME data.
	Prefix string `description:"Prefix for ACME data keys." json:"prefix,omitempty" toml:"prefix,omitempty" yaml:"prefix,omitempty"`

	// TLS configuration for the KV store connection.
	TLS *types.ClientTLS `description:"TLS configuration for KV store." json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty"`

	// Username for authentication.
	Username string `description:"Username for KV store authentication." json:"username,omitempty" toml:"username,omitempty" yaml:"username,omitempty" loggable:"false"`

	// Password for authentication.
	Password string `description:"Password for KV store authentication." json:"password,omitempty" toml:"password,omitempty" yaml:"password,omitempty" loggable:"false"`

	// LockTimeout is the timeout for acquiring locks during certificate operations.
	LockTimeout time.Duration `description:"Lock timeout for certificate operations." json:"lockTimeout,omitempty" toml:"lockTimeout,omitempty" yaml:"lockTimeout,omitempty"`
}

// SetDefaults sets the default values for KVStoreConfig.
func (c *KVStoreConfig) SetDefaults() {
	c.Prefix = DefaultPrefix
	c.LockTimeout = 30 * time.Second
}

// KVStore implements the Store interface using a distributed key-value store.
// This allows multiple Traefik instances to share ACME certificates,
// preventing conflicts and rate limiting issues with Let's Encrypt.
type KVStore struct {
	kvClient    store.Store
	prefix      string
	lockTimeout time.Duration

	lock       sync.RWMutex
	storedData map[string]*StoredData

	// locks is used to track distributed locks for certificate operations.
	locks map[string]store.Locker
}

// NewKVStore creates a new KVStore with the given configuration.
func NewKVStore(ctx context.Context, storeType string, config valkeyrie.Config, kvConfig *KVStoreConfig) (*KVStore, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	kvClient, err := valkeyrie.NewStore(ctx, storeType, kvConfig.Endpoints, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KV store: %w", err)
	}

	// Test connection
	testKey := fmt.Sprintf("%s/.test", kvConfig.Prefix)
	if err := kvClient.Put(ctx, testKey, []byte("test"), nil); err != nil {
		return nil, fmt.Errorf("failed to write to KV store (connection test): %w", err)
	}
	_ = kvClient.Delete(ctx, testKey)

	logger.Info().Msgf("Connected to KV store at %v with prefix %s", kvConfig.Endpoints, kvConfig.Prefix)

	return &KVStore{
		kvClient:    kvClient,
		prefix:      kvConfig.Prefix,
		lockTimeout: kvConfig.LockTimeout,
		storedData:  make(map[string]*StoredData),
		locks:       make(map[string]store.Locker),
	}, nil
}

// GetAccount returns the ACME Account for the given resolver.
func (s *KVStore) GetAccount(resolverName string) (*Account, error) {
	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}
	return storedData.Account, nil
}

// Client returns the underlying KV store client.
// This is used to create distributed HTTP challenge providers.
func (s *KVStore) Client() store.Store {
	return s.kvClient
}

// SaveAccount stores the ACME Account for the given resolver.
func (s *KVStore) SaveAccount(resolverName string, account *Account) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	storedData, err := s.getUnsafe(resolverName)
	if err != nil {
		return err
	}

	storedData.Account = account
	return s.saveUnsafe(resolverName, storedData)
}

// GetCertificates returns the ACME Certificates for the given resolver.
func (s *KVStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}
	return storedData.Certificates, nil
}

// SaveCertificates stores the ACME Certificates for the given resolver.
// This method uses distributed locking to prevent race conditions between
// multiple Traefik instances.
func (s *KVStore) SaveCertificates(resolverName string, certificates []*CertAndStore) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	storedData, err := s.getUnsafe(resolverName)
	if err != nil {
		return err
	}

	storedData.Certificates = certificates
	return s.saveUnsafe(resolverName, storedData)
}

// AcquireLock attempts to acquire a distributed lock for the given domain.
// This prevents multiple Traefik instances from simultaneously requesting
// certificates for the same domain.
func (s *KVStore) AcquireLock(ctx context.Context, domain string) (store.Locker, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	lockKey := fmt.Sprintf("%s/locks/%s", s.prefix, domain)

	locker, err := s.kvClient.NewLock(ctx, lockKey, &store.LockOptions{
		TTL: s.lockTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create lock for domain %s: %w", domain, err)
	}

	// Try to acquire the lock with timeout
	lockCtx, cancel := context.WithTimeout(ctx, s.lockTimeout)
	defer cancel()

	lockChan, err := locker.Lock(lockCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock for domain %s: %w", domain, err)
	}

	// Start a goroutine to monitor lock loss
	go func() {
		select {
		case <-lockChan:
			logger.Warn().Str("domain", domain).Msg("Lost distributed lock for domain")
		case <-ctx.Done():
			return
		}
	}()

	logger.Debug().Str("domain", domain).Msg("Acquired distributed lock for domain")

	s.lock.Lock()
	s.locks[domain] = locker
	s.lock.Unlock()

	return locker, nil
}

// ReleaseLock releases the distributed lock for the given domain.
func (s *KVStore) ReleaseLock(domain string) error {
	s.lock.Lock()
	locker, exists := s.locks[domain]
	if exists {
		delete(s.locks, domain)
	}
	s.lock.Unlock()

	if !exists {
		return nil
	}

	if err := locker.Unlock(context.Background()); err != nil {
		return fmt.Errorf("failed to release lock for domain %s: %w", domain, err)
	}

	log.Debug().Str(logs.ProviderName, "acme-kv").Str("domain", domain).Msg("Released distributed lock for domain")
	return nil
}

// Watch sets up a watch on the KV store for ACME data changes.
// This allows Traefik instances to sync certificate updates from other instances.
func (s *KVStore) Watch(ctx context.Context, resolverName string) (<-chan struct{}, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	key := fmt.Sprintf("%s/data/%s", s.prefix, resolverName)

	events, err := s.kvClient.Watch(ctx, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to watch KV store: %w", err)
	}

	updates := make(chan struct{}, 1)

	go func() {
		defer close(updates)
		for {
			select {
			case <-ctx.Done():
				return
			case pair, ok := <-events:
				if !ok {
					logger.Warn().Msg("KV store watch channel closed")
					return
				}
				if pair == nil {
					continue
				}

				// Invalidate local cache so next get() fetches fresh data
				s.lock.Lock()
				delete(s.storedData, resolverName)
				s.lock.Unlock()

				// Notify watchers
				select {
				case updates <- struct{}{}:
				default:
					// Channel already has pending notification
				}

				logger.Debug().Str("resolver", resolverName).Msg("ACME data updated in KV store")
			}
		}
	}()

	return updates, nil
}

// get retrieves the StoredData for the given resolver from the KV store.
func (s *KVStore) get(resolverName string) (*StoredData, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.getUnsafe(resolverName)
}

// getUnsafe retrieves the StoredData without acquiring locks.
// Caller must hold s.lock.
func (s *KVStore) getUnsafe(resolverName string) (*StoredData, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()
	ctx := context.Background()

	// Check local cache first
	if cached, ok := s.storedData[resolverName]; ok {
		return cached, nil
	}

	key := fmt.Sprintf("%s/data/%s", s.prefix, resolverName)

	pair, err := s.kvClient.Get(ctx, key, nil)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			// No data yet, return empty StoredData
			s.storedData[resolverName] = &StoredData{}
			return s.storedData[resolverName], nil
		}
		return nil, fmt.Errorf("failed to get ACME data from KV store: %w", err)
	}

	// Decompress the data (certificates can be large, we compress them)
	data, err := decompress(pair.Value)
	if err != nil {
		// Try uncompressed for backward compatibility
		data = pair.Value
	}

	storedData := &StoredData{}
	if err := json.Unmarshal(data, storedData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ACME data: %w", err)
	}

	// Filter out empty certificates
	var validCerts []*CertAndStore
	for _, cert := range storedData.Certificates {
		if len(cert.Certificate.Certificate) > 0 && len(cert.Key) > 0 {
			validCerts = append(validCerts, cert)
		} else {
			logger.Debug().Msgf("Filtering empty certificate for %v", cert.Domain.ToStrArray())
		}
	}
	storedData.Certificates = validCerts

	s.storedData[resolverName] = storedData
	return storedData, nil
}

// saveUnsafe saves the StoredData without acquiring locks.
// Caller must hold s.lock.
func (s *KVStore) saveUnsafe(resolverName string, storedData *StoredData) error {
	ctx := context.Background()

	s.storedData[resolverName] = storedData

	data, err := json.Marshal(storedData)
	if err != nil {
		return fmt.Errorf("failed to marshal ACME data: %w", err)
	}

	// Compress the data to reduce storage size
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("failed to compress ACME data: %w", err)
	}

	key := fmt.Sprintf("%s/data/%s", s.prefix, resolverName)

	if err := s.kvClient.Put(ctx, key, compressed, nil); err != nil {
		return fmt.Errorf("failed to save ACME data to KV store: %w", err)
	}

	log.Debug().Str(logs.ProviderName, "acme-kv").
		Str("resolver", resolverName).
		Int("size", len(compressed)).
		Msg("Saved ACME data to KV store")

	return nil
}

// compress compresses data using gzip.
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompress decompresses gzip data.
func decompress(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}
