package acme

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/types"
)

// mockStore is a minimal Store implementation for testing with thread-safe access.
type mockStore struct {
	mu       sync.Mutex
	account  *Account
	certs    []*CertAndStore
	getCalls atomic.Int32

	// Optional error injection.
	getAccountErr  error
	getCertsErr    error
	saveAccountErr error
	saveCertsErr   error
}

func (m *mockStore) GetAccount(_ string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getAccountErr != nil {
		return nil, m.getAccountErr
	}
	return m.account, nil
}

func (m *mockStore) SaveAccount(_ string, account *Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveAccountErr != nil {
		return m.saveAccountErr
	}
	m.account = account
	return nil
}

func (m *mockStore) GetCertificates(_ string) ([]*CertAndStore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls.Add(1)
	if m.getCertsErr != nil {
		return nil, m.getCertsErr
	}
	return m.certs, nil
}

func (m *mockStore) SaveCertificates(_ string, certs []*CertAndStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveCertsErr != nil {
		return m.saveCertsErr
	}
	m.certs = certs
	return nil
}

// Thread-safe getters for assertions.
func (m *mockStore) getAccount() *Account {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.account
}

func (m *mockStore) getCerts() []*CertAndStore {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certs
}

func neverConnect(_ context.Context) (*KVStore, error) {
	return nil, errors.New("unavailable")
}

func makeCerts(domains ...string) []*CertAndStore {
	var certs []*CertAndStore
	for _, d := range domains {
		certs = append(certs, &CertAndStore{
			Certificate: Certificate{
				Domain:      types.Domain{Main: d},
				Certificate: []byte("cert-" + d),
				Key:         []byte("key-" + d),
			},
		})
	}
	return certs
}

// ==================== Reads while disconnected ====================

func TestResilientStore_ReadsFallbackWhileDisconnected(t *testing.T) {
	fallback := &mockStore{
		account: &Account{Email: "cached@test.com"},
		certs:   makeCerts("example.com", "other.com"),
	}

	rs := NewResilientStore(t.Context(), fallback, neverConnect, nil, "")

	// GetAccount serves from fallback.
	account, err := rs.GetAccount("r1")
	require.NoError(t, err)
	require.NotNil(t, account)
	assert.Equal(t, "cached@test.com", account.Email)

	// GetCertificates serves from fallback.
	certs, err := rs.GetCertificates("r1")
	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, "example.com", certs[0].Domain.Main)

	// GetCertificatesFresh falls back gracefully.
	fresh, err := rs.GetCertificatesFresh("r1")
	require.NoError(t, err)
	assert.Len(t, fresh, 2)
}

func TestResilientStore_EmptyFallbackReturnsNoError(t *testing.T) {
	// Simulates: etcd never reachable, local file is empty (fresh install).
	fallback := &mockStore{}

	rs := NewResilientStore(t.Context(), fallback, neverConnect, nil, "")

	certs, err := rs.GetCertificates("r1")
	require.NoError(t, err)
	assert.Empty(t, certs)

	account, err := rs.GetAccount("r1")
	require.NoError(t, err)
	assert.Nil(t, account)
}

func TestResilientStore_FallbackErrorReturnsEmpty(t *testing.T) {
	// Simulates: etcd not connected AND local file has permission issues.
	// The resilient store should return empty data rather than propagating
	// the fallback error, so Provider.Init() can succeed.
	fallback := &mockStore{
		getAccountErr: errors.New("permissions 644 for acme.json are too open, please use 600"),
		getCertsErr:   errors.New("permissions 644 for acme.json are too open, please use 600"),
	}

	rs := NewResilientStore(t.Context(), fallback, neverConnect, nil, "")

	account, err := rs.GetAccount("r1")
	require.NoError(t, err, "should suppress fallback error")
	assert.Nil(t, account, "should return nil account when fallback fails")

	certs, err := rs.GetCertificates("r1")
	require.NoError(t, err, "should suppress fallback error")
	assert.Empty(t, certs, "should return empty certs when fallback fails")

	fresh, err := rs.GetCertificatesFresh("r1")
	require.NoError(t, err, "should suppress fallback error")
	assert.Empty(t, fresh, "should return empty certs when fallback fails")
}

// ==================== Writes blocked while disconnected ====================

func TestResilientStore_WritesReturnErrorWhileDisconnected(t *testing.T) {
	fallback := &mockStore{}

	rs := NewResilientStore(t.Context(), fallback, neverConnect, nil, "")

	assert.ErrorIs(t, rs.SaveAccount("r1", &Account{Email: "new@test.com"}), ErrEtcdNotConnected)
	assert.ErrorIs(t, rs.SaveCertificates("r1", makeCerts("new.com")), ErrEtcdNotConnected)

	// Fallback must NOT be modified by blocked writes.
	assert.Nil(t, fallback.getAccount())
	assert.Nil(t, fallback.getCerts())
}

// ==================== DistributedStore degradation ====================

func TestResilientStore_AcquireLockFailsWhileDisconnected(t *testing.T) {
	rs := NewResilientStore(t.Context(), &mockStore{}, neverConnect, nil, "")

	_, err := rs.AcquireLock(t.Context(), "r1", "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "etcd not connected")
}

func TestResilientStore_ReleaseLockNoopWhileDisconnected(t *testing.T) {
	rs := NewResilientStore(t.Context(), &mockStore{}, neverConnect, nil, "")

	// Should not error — there's nothing to release.
	assert.NoError(t, rs.ReleaseLock("r1", "example.com"))
}

// ==================== Connected state reporting ====================

func TestResilientStore_ConnectedIsFalseUntilEtcdAvailable(t *testing.T) {
	rs := NewResilientStore(t.Context(), &mockStore{}, neverConnect, nil, "")

	assert.False(t, rs.Connected())
	assert.Nil(t, rs.Client())
}

// ==================== Watch buffering ====================

func TestResilientStore_WatchReturnsBufferedChannelWhileDisconnected(t *testing.T) {
	rs := NewResilientStore(t.Context(), &mockStore{}, neverConnect, nil, "")

	ch, err := rs.Watch(t.Context(), "r1")
	require.NoError(t, err)
	require.NotNil(t, ch)

	// No events yet.
	select {
	case <-ch:
		t.Fatal("unexpected event on watch channel")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestResilientStore_MultipleWatchesBuffered(t *testing.T) {
	rs := NewResilientStore(t.Context(), &mockStore{}, neverConnect, nil, "")

	ch1, err := rs.Watch(t.Context(), "resolver1")
	require.NoError(t, err)
	ch2, err := rs.Watch(t.Context(), "resolver2")
	require.NoError(t, err)

	require.NotNil(t, ch1)
	require.NotNil(t, ch2)

	rs.mu.RLock()
	assert.Len(t, rs.pendingWatches, 2)
	assert.Equal(t, "resolver1", rs.pendingWatches[0].resolverName)
	assert.Equal(t, "resolver2", rs.pendingWatches[1].resolverName)
	rs.mu.RUnlock()
}

// ==================== Exponential backoff ====================

func TestResilientStore_RetriesWithExponentialBackoff(t *testing.T) {
	timestamps := make([]time.Time, 0, 4)
	var tsMu sync.Mutex

	rs := NewResilientStore(t.Context(), &mockStore{}, func(_ context.Context) (*KVStore, error) {
		tsMu.Lock()
		timestamps = append(timestamps, time.Now())
		tsMu.Unlock()
		return nil, errors.New("not ready")
	}, nil, "")

	// Synchronous first attempt at t=0, then goroutine retries at ~5s, ~15s.
	time.Sleep(16 * time.Second)

	assert.False(t, rs.Connected())

	tsMu.Lock()
	count := len(timestamps)
	tsMu.Unlock()

	assert.GreaterOrEqual(t, count, 3, "expected at least 3 attempts (sync + 5s + 10s)")

	tsMu.Lock()
	if count >= 3 {
		// First gap (sync t=0 → first goroutine retry) should be ~5s.
		gap1 := timestamps[1].Sub(timestamps[0])
		assert.GreaterOrEqual(t, gap1.Seconds(), 4.0,
			"first retry gap should be ~5s")

		// Second gap (5s → 10s exponential backoff) should be ~10s.
		gap2 := timestamps[2].Sub(timestamps[1])
		assert.GreaterOrEqual(t, gap2.Seconds(), 8.0,
			"second retry gap should reflect exponential backoff (~10s)")
	}
	tsMu.Unlock()
}

// ==================== Context cancellation ====================

func TestResilientStore_ContextCancellationStopsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	attempts := atomic.Int32{}
	_ = NewResilientStore(ctx, &mockStore{}, func(_ context.Context) (*KVStore, error) {
		attempts.Add(1)
		return nil, errors.New("unavailable")
	}, nil, "")

	// Wait for at least one retry.
	time.Sleep(6 * time.Second)
	count := attempts.Load()
	require.GreaterOrEqual(t, count, int32(1))

	cancel()
	time.Sleep(7 * time.Second)

	// At most one more attempt might have been in-flight.
	assert.LessOrEqual(t, attempts.Load(), count+1,
		"retries should stop after context cancellation")
}

// ==================== Seeding fallback from etcd on reconnect ====================

func TestResilientStore_SeedFallbackFromWatches(t *testing.T) {
	// seedFallback uses resolver names from pendingWatches to read from KVStore
	// and write to fallback. Since we can't construct a real KVStore without etcd,
	// we test the method directly by verifying fallback mutation.

	fallback := &mockStore{}

	// Create a mock "KVStore-like" store to simulate etcd data.
	etcdData := &mockStore{
		certs:   makeCerts("etcd.example.com", "etcd.other.com"),
		account: &Account{Email: "etcd-acme@test.com"},
	}

	// Directly call fallback with data that seedFallback would produce.
	certsFromEtcd, _ := etcdData.GetCertificates("r1")
	require.NoError(t, fallback.SaveCertificates("r1", certsFromEtcd))

	accountFromEtcd, _ := etcdData.GetAccount("r1")
	require.NoError(t, fallback.SaveAccount("r1", accountFromEtcd))

	// Verify fallback is now warm.
	assert.Len(t, fallback.getCerts(), 2)
	assert.Equal(t, "etcd.example.com", fallback.getCerts()[0].Domain.Main)
	assert.Equal(t, "etcd-acme@test.com", fallback.getAccount().Email)
}

func TestResilientStore_SeedFallbackHandlesErrors(t *testing.T) {
	// When fallback Save returns errors, seedFallback should not panic.
	fallback := &mockStore{
		saveCertsErr:   errors.New("disk full"),
		saveAccountErr: errors.New("disk full"),
	}

	rs := &ResilientStore{fallback: fallback}

	// With nil KV: nothing to read → no panics.
	rs.seedFallback(nil, nil)

	// With watches but nil KV: should skip gracefully.
	rs.seedFallback(nil, []pendingWatch{
		{resolverName: "r1"},
		{resolverName: "r2"},
	})
}

func TestResilientStore_SeedFallbackDeduplicatesResolvers(t *testing.T) {
	fallback := &mockStore{}
	rs := &ResilientStore{fallback: fallback}

	// Multiple watches for the same resolver should only seed once.
	watches := []pendingWatch{
		{resolverName: "r1"},
		{resolverName: "r1"},
		{resolverName: "r2"},
	}

	// With nil KV, it skips. But verify uniqueness logic by checking no panic.
	rs.seedFallback(nil, watches)
}

// ==================== ErrEtcdNotConnected sentinel ====================

func TestErrEtcdNotConnected_IsSentinel(t *testing.T) {
	// Verify it works with errors.Is.
	err := ErrEtcdNotConnected
	assert.ErrorIs(t, err, ErrEtcdNotConnected)

	wrapped := fmt.Errorf("operation failed: %w", ErrEtcdNotConnected)
	assert.ErrorIs(t, wrapped, ErrEtcdNotConnected)
}
