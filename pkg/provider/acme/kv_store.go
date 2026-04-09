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

// KVStoreConfig holds KV store connection settings for ACME storage.
type KVStoreConfig struct {
	Endpoints   []string         `description:"KV store endpoints." json:"endpoints,omitempty" toml:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	Prefix      string           `description:"Prefix for ACME data keys." json:"prefix,omitempty" toml:"prefix,omitempty" yaml:"prefix,omitempty"`
	TLS         *types.ClientTLS `description:"TLS configuration for KV store." json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty"`
	Username    string           `description:"Username for KV store authentication." json:"username,omitempty" toml:"username,omitempty" yaml:"username,omitempty" loggable:"false"`
	Password    string           `description:"Password for KV store authentication." json:"password,omitempty" toml:"password,omitempty" yaml:"password,omitempty" loggable:"false"`
	LockTimeout time.Duration    `description:"Lock timeout for certificate operations." json:"lockTimeout,omitempty" toml:"lockTimeout,omitempty" yaml:"lockTimeout,omitempty"`
}

// SetDefaults sets the default values for KVStoreConfig.
func (c *KVStoreConfig) SetDefaults() {
	c.Prefix = DefaultPrefix
	c.LockTimeout = 30 * time.Second
}

// KVStore implements the Store and DistributedStore interfaces using a KV backend.
type KVStore struct {
	kvClient    store.Store
	prefix      string
	lockTimeout time.Duration

	lock       sync.RWMutex
	storedData map[string]*StoredData

	locks        map[string]store.Locker       // active distributed locks by resolver/domain
	lockMonitors map[string]context.CancelFunc // cancel funcs for lock-loss monitor goroutines
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
		kvClient:     kvClient,
		prefix:       kvConfig.Prefix,
		lockTimeout:  kvConfig.LockTimeout,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
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

// Client returns the underlying KV store client for creating additional providers.
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

// GetCertificatesFresh fetches certificates directly from the KV store, bypassing cache.
// Use after acquiring a lock to ensure visibility of certificates from other replicas.
func (s *KVStore) GetCertificatesFresh(resolverName string) ([]*CertAndStore, error) {
	s.lock.Lock()
	// Invalidate cache to force a fresh fetch
	delete(s.storedData, resolverName)
	s.lock.Unlock()

	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}
	return storedData.Certificates, nil
}

// SaveCertificates stores ACME certificates for the given resolver.
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

// AcquireLock acquires a distributed lock for certificate operations on a domain.
// The lock is namespaced by resolver to allow multiple resolvers to handle the same domain.
func (s *KVStore) AcquireLock(ctx context.Context, resolverName, domain string) (store.Locker, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	lockKey := fmt.Sprintf("%s/%s/locks/%s", s.prefix, resolverName, domain)

	// Use a background context for the lock lifecycle so that the lock session
	// (and its TTL renewal) survives independently of the caller's context.
	// The caller's context is only used for the acquisition timeout below.
	locker, err := s.kvClient.NewLock(context.Background(), lockKey, &store.LockOptions{
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

	lockMapKey := fmt.Sprintf("%s/%s", resolverName, domain)
	logger.Debug().Str("resolver", resolverName).Str("domain", domain).Msg("Acquired distributed lock")

	// Monitor for unexpected lock loss (e.g. etcd TTL expiry, connection drop).
	// A cancel func is stored alongside the locker so that ReleaseLock can
	// stop the goroutine on normal unlock — without it the goroutine would
	// fire a spurious "Lost distributed lock" warning on every release.
	monitorCtx, monitorCancel := context.WithCancel(ctx)

	go func() {
		select {
		case <-lockChan:
			// Only warn if the monitor wasn't canceled by a normal ReleaseLock.
			if monitorCtx.Err() == nil {
				logger.Warn().Str("resolver", resolverName).Str("domain", domain).Msg("Lost distributed lock")
			}
		case <-monitorCtx.Done():
			return
		}
	}()

	s.lock.Lock()
	s.locks[lockMapKey] = locker
	s.lockMonitors[lockMapKey] = monitorCancel
	s.lock.Unlock()

	return locker, nil
}

// ReleaseLock releases the distributed lock for the given resolver and domain.
func (s *KVStore) ReleaseLock(resolverName, domain string) error {
	lockMapKey := fmt.Sprintf("%s/%s", resolverName, domain)

	s.lock.Lock()
	locker, exists := s.locks[lockMapKey]
	if exists {
		delete(s.locks, lockMapKey)
	}
	// Cancel the monitor goroutine BEFORE unlocking so it doesn't
	// fire a spurious "Lost distributed lock" warning.
	if cancel, ok := s.lockMonitors[lockMapKey]; ok {
		cancel()
		delete(s.lockMonitors, lockMapKey)
	}
	s.lock.Unlock()

	if !exists {
		return nil
	}

	if err := locker.Unlock(context.Background()); err != nil {
		return fmt.Errorf("failed to release lock for resolver %s domain %s: %w", resolverName, domain, err)
	}

	log.Debug().Str(logs.ProviderName, "acme-kv").Str("resolver", resolverName).Str("domain", domain).Msg("Released distributed lock")
	return nil
}

// Watch subscribes to certificate updates from the KV store for cross-replica sync.
func (s *KVStore) Watch(ctx context.Context, resolverName string) (<-chan struct{}, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	key := fmt.Sprintf("%s/%s/data", s.prefix, resolverName)

	// Ensure the key exists before watching. Some KV backends (e.g. etcd)
	// return "key not found" when watching a non-existent key.
	_, err := s.kvClient.Get(ctx, key, nil)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			emptyData, marshalErr := json.Marshal(&StoredData{})
			if marshalErr != nil {
				return nil, fmt.Errorf("failed to marshal initial ACME data: %w", marshalErr)
			}
			compressed, compressErr := compress(emptyData)
			if compressErr != nil {
				return nil, fmt.Errorf("failed to compress initial ACME data: %w", compressErr)
			}
			if putErr := s.kvClient.Put(ctx, key, compressed, nil); putErr != nil {
				return nil, fmt.Errorf("failed to initialize KV store key for watch: %w", putErr)
			}
			logger.Debug().Str("resolver", resolverName).Msg("Initialized empty ACME data key for watch")
		} else {
			return nil, fmt.Errorf("failed to check KV store key before watch: %w", err)
		}
	}

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

// get retrieves StoredData, using local cache when available.
func (s *KVStore) get(resolverName string) (*StoredData, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.getUnsafe(resolverName)
}

// getUnsafe retrieves StoredData without locking. Caller must hold s.lock.
func (s *KVStore) getUnsafe(resolverName string) (*StoredData, error) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()
	ctx := context.Background()

	if cached, ok := s.storedData[resolverName]; ok {
		return cached, nil
	}

	key := fmt.Sprintf("%s/%s/data", s.prefix, resolverName)

	pair, err := s.kvClient.Get(ctx, key, nil)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			s.storedData[resolverName] = &StoredData{}
			return s.storedData[resolverName], nil
		}
		return nil, fmt.Errorf("failed to get ACME data from KV store: %w", err)
	}

	data, err := decompress(pair.Value)
	if err != nil {
		data = pair.Value // Try uncompressed for backward compatibility
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

	key := fmt.Sprintf("%s/%s/data", s.prefix, resolverName)

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
