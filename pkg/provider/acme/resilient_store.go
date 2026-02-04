package acme

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kvtools/valkeyrie/store"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
)

// Compile-time interface checks.
var (
	_ Store            = (*ResilientStore)(nil)
	_ DistributedStore = (*ResilientStore)(nil)
)

const (
	initialRetryInterval = 5 * time.Second
	maxRetryInterval     = 5 * time.Minute
)

// pendingWatch holds the parameters for a Watch call made before the primary connected.
type pendingWatch struct {
	ctx          context.Context
	resolverName string
	ch           chan struct{}
}

// ErrEtcdNotConnected is returned for write operations when the KV backend is unavailable.
// This prevents state divergence between local storage and etcd.
var ErrEtcdNotConnected = errors.New("etcd not connected: certificate operations suspended")

// ResilientStore wraps a KVStore with automatic background reconnection.
// While the KV backend is unavailable:
//   - Reads (GetAccount, GetCertificates) serve cached/existing data from the local fallback
//   - Writes (SaveAccount, SaveCertificates) return ErrEtcdNotConnected to prevent divergence
//   - AcquireLock returns an error, so the Provider skips cert issuance entirely
//   - Watch channels are buffered and forwarded once connected
//
// When the backend reconnects, the store promotes to full distributed mode
// and also sets up the DistributedChallengeHTTP on the associated challenge handler.
type ResilientStore struct {
	mu             sync.RWMutex
	primary        *KVStore // nil until the KV backend connects
	fallback       Store    // local store — reads only while disconnected
	pendingWatches []pendingWatch

	challenge       *ResilientChallengeHTTP // promoted on connect; may be nil
	challengePrefix string                  // KV prefix for distributed challenges
}

// NewResilientStore creates a store that wraps a KV backend with automatic
// reconnection and local fallback.
//
// The first connection attempt is made synchronously so that Provider.Init()
// sees a connected store when etcd is available. If that fails, a background
// goroutine retries with exponential backoff (5s → 5min).
//
// Reads are served by fallback until the backend connects.
// Writes and lock operations are blocked while disconnected.
// If challenge is non-nil, a DistributedChallengeHTTP will be created and
// set on it once the KV backend connects.
func NewResilientStore(
	ctx context.Context,
	fallback Store,
	createFn func(ctx context.Context) (*KVStore, error),
	challenge *ResilientChallengeHTTP,
	challengePrefix string,
) *ResilientStore {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	rs := &ResilientStore{
		fallback:        fallback,
		challenge:       challenge,
		challengePrefix: challengePrefix,
	}

	// Try to connect synchronously first. When etcd is available (the common
	// case), the store is fully operational before Provider.Init() runs,
	// so the local fallback is never read from.
	kv, err := createFn(ctx)
	if err != nil {
		logger.Warn().Err(err).
			Msg("Initial etcd connection failed, starting background reconnection with local fallback")
		go rs.connectLoop(ctx, createFn)
	} else {
		rs.primary = kv
		rs.onConnected(ctx, kv, nil)
	}

	return rs
}

// connectLoop retries the KV backend connection in the background with
// exponential backoff. Only started when the synchronous first attempt fails.
func (rs *ResilientStore) connectLoop(ctx context.Context, createFn func(ctx context.Context) (*KVStore, error)) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	backoff := initialRetryInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		kv, err := createFn(ctx)
		if err != nil {
			backoff = min(backoff*2, maxRetryInterval)
			logger.Warn().Err(err).Dur("nextRetry", backoff).
				Msg("Etcd connection attempt failed, will retry")
			continue
		}

		rs.mu.Lock()
		rs.primary = kv
		pending := rs.pendingWatches
		rs.pendingWatches = nil
		rs.mu.Unlock()

		// Start any watches that were buffered before connection was established.
		for _, pw := range pending {
			go rs.forwardWatch(pw, kv)
		}

		rs.onConnected(ctx, kv, pending)
		return
	}
}

// onConnected performs post-connection setup: seeds the local fallback store
// with data from etcd and promotes the HTTP challenge handler to distributed mode.
func (rs *ResilientStore) onConnected(ctx context.Context, kv *KVStore, pending []pendingWatch) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	// Seed local fallback so restarts without etcd have warm certs.
	rs.seedFallback(kv, pending)

	// Promote the HTTP challenge handler to distributed mode.
	if rs.challenge != nil && rs.challengePrefix != "" {
		distHTTP := NewDistributedChallengeHTTP(kv.Client(), rs.challengePrefix)
		if err := distHTTP.WatchChallenges(ctx); err != nil {
			logger.Warn().Err(err).Msg("Failed to start distributed HTTP challenge watch")
		}
		rs.challenge.SetDistributed(distHTTP)
	}

	logger.Info().Msg("Successfully connected to etcd for distributed ACME storage")
}

// seedFallback copies certificates and account data from etcd to the local
// fallback store, so that on a restart without etcd the local file has warm data.
func (rs *ResilientStore) seedFallback(kv *KVStore, watches []pendingWatch) {
	if kv == nil || len(watches) == 0 {
		return
	}

	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	// Collect unique resolver names from buffered watches.
	seen := make(map[string]struct{})
	for _, pw := range watches {
		seen[pw.resolverName] = struct{}{}
	}

	for resolverName := range seen {
		certs, err := kv.GetCertificates(resolverName)
		if err != nil {
			logger.Warn().Err(err).Str("resolver", resolverName).
				Msg("Failed to read certificates from etcd for local fallback seeding")
			continue
		}

		if err := rs.fallback.SaveCertificates(resolverName, certs); err != nil {
			logger.Warn().Err(err).Str("resolver", resolverName).
				Msg("Failed to seed local fallback with certificates from etcd")
		} else {
			logger.Info().Str("resolver", resolverName).Int("certs", len(certs)).
				Msg("Seeded local fallback store with certificates from etcd")
		}

		account, err := kv.GetAccount(resolverName)
		if err != nil {
			logger.Warn().Err(err).Str("resolver", resolverName).
				Msg("Failed to read account from etcd for local fallback seeding")
			continue
		}

		if account != nil {
			if err := rs.fallback.SaveAccount(resolverName, account); err != nil {
				logger.Warn().Err(err).Str("resolver", resolverName).
					Msg("Failed to seed local fallback with account from etcd")
			}
		}
	}
}

// forwardWatch connects a pending watch channel to the real KV store watch.
// It also sends an initial notification so that the provider re-evaluates
// certificate state immediately after reconnection.
func (rs *ResilientStore) forwardWatch(pw pendingWatch, kv *KVStore) {
	logger := log.With().Str(logs.ProviderName, "acme-kv").Logger()

	// Trigger an immediate certificate check so the provider can issue any
	// certificates that were pending while etcd was down.
	select {
	case pw.ch <- struct{}{}:
	default:
	}

	src, err := kv.Watch(pw.ctx, pw.resolverName)
	if err != nil {
		logger.Warn().Err(err).Str("resolver", pw.resolverName).
			Msg("Failed to start deferred distributed watch after reconnection")
		return
	}

	logger.Info().Str("resolver", pw.resolverName).
		Msg("Started deferred distributed watch after etcd reconnection")

	for {
		select {
		case <-pw.ctx.Done():
			return
		case _, ok := <-src:
			if !ok {
				close(pw.ch)
				return
			}
			select {
			case pw.ch <- struct{}{}:
			default:
			}
		}
	}
}

// Connected reports whether the KV backend is available.
func (rs *ResilientStore) Connected() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.primary != nil
}

// Client returns the underlying KV client, or nil if not yet connected.
func (rs *ResilientStore) Client() store.Store {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.primary != nil {
		return rs.primary.Client()
	}
	return nil
}

// --- Store interface ---
// Reads: serve from primary if connected, fallback otherwise (existing certs stay available).
// Writes: only go to primary; error when disconnected to prevent local/etcd divergence.

func (rs *ResilientStore) GetAccount(resolverName string) (*Account, error) {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p != nil {
		return p.GetAccount(resolverName)
	}

	account, err := rs.fallback.GetAccount(resolverName)
	if err != nil {
		// The fallback is a warm cache; if it is broken (e.g. file-permission
		// issues) return empty data instead of failing. The primary will
		// provide real data once it reconnects.
		log.Warn().Err(err).Str("resolver", resolverName).
			Msg("Fallback store read failed, returning empty account (etcd not connected)")
		return nil, nil
	}
	return account, nil
}

func (rs *ResilientStore) SaveAccount(resolverName string, account *Account) error {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p == nil {
		return ErrEtcdNotConnected
	}

	if err := p.SaveAccount(resolverName, account); err != nil {
		return err
	}

	// Mirror to local fallback so it stays warm for restarts without etcd.
	if err := rs.fallback.SaveAccount(resolverName, account); err != nil {
		log.Warn().Err(err).Str("resolver", resolverName).
			Msg("Failed to mirror account to local fallback store")
	}

	return nil
}

func (rs *ResilientStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p != nil {
		return p.GetCertificates(resolverName)
	}

	certs, err := rs.fallback.GetCertificates(resolverName)
	if err != nil {
		// Same treatment as GetAccount: fallback is a warm cache.
		log.Warn().Err(err).Str("resolver", resolverName).
			Msg("Fallback store read failed, returning empty certificates (etcd not connected)")
		return nil, nil
	}
	return certs, nil
}

func (rs *ResilientStore) SaveCertificates(resolverName string, certs []*CertAndStore) error {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p == nil {
		return ErrEtcdNotConnected
	}

	if err := p.SaveCertificates(resolverName, certs); err != nil {
		return err
	}

	// Mirror to local fallback so it stays warm for restarts without etcd.
	if err := rs.fallback.SaveCertificates(resolverName, certs); err != nil {
		log.Warn().Err(err).Str("resolver", resolverName).
			Msg("Failed to mirror certificates to local fallback store")
	}

	return nil
}

// --- DistributedStore interface (graceful degradation when disconnected) ---

func (rs *ResilientStore) AcquireLock(ctx context.Context, resolverName, domain string) (store.Locker, error) {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p == nil {
		return nil, errors.New("distributed lock unavailable: etcd not connected")
	}
	return p.AcquireLock(ctx, resolverName, domain)
}

func (rs *ResilientStore) ReleaseLock(resolverName, domain string) error {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p == nil {
		return nil
	}
	return p.ReleaseLock(resolverName, domain)
}

// Watch returns a channel that receives notifications when certificates change in the KV store.
// If the backend is not yet connected, the watch is buffered and automatically
// forwarded once the connection is established.
func (rs *ResilientStore) Watch(ctx context.Context, resolverName string) (<-chan struct{}, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.primary != nil {
		return rs.primary.Watch(ctx, resolverName)
	}

	// Buffer the watch request; it will be started when the primary connects.
	ch := make(chan struct{}, 1)
	rs.pendingWatches = append(rs.pendingWatches, pendingWatch{
		ctx:          ctx,
		resolverName: resolverName,
		ch:           ch,
	})
	return ch, nil
}

func (rs *ResilientStore) GetCertificatesFresh(resolverName string) ([]*CertAndStore, error) {
	rs.mu.RLock()
	p := rs.primary
	rs.mu.RUnlock()
	if p == nil {
		// No cache issue with local store, regular GetCertificates is equivalent.
		certs, err := rs.fallback.GetCertificates(resolverName)
		if err != nil {
			log.Warn().Err(err).Str("resolver", resolverName).
				Msg("Fallback store read failed, returning empty certificates (etcd not connected)")
			return nil, nil
		}
		return certs, nil
	}

	certs, err := p.GetCertificatesFresh(resolverName)
	if err != nil {
		return nil, err
	}

	// Mirror fresh data to local fallback.
	if mirrorErr := rs.fallback.SaveCertificates(resolverName, certs); mirrorErr != nil {
		log.Warn().Err(mirrorErr).Str("resolver", resolverName).
			Msg("Failed to mirror fresh certificates to local fallback store")
	}

	return certs, nil
}
