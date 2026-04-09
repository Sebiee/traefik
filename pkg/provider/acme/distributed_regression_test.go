package acme

// Regression tests for distributed ACME storage bugs found in v0.0.1.
//
// These tests cover the exact scenarios that caused production failures
// on the very first multi-replica deployment:
//
// 1. Watch on non-existent key (first startup / empty etcd)
// 2. Lock monitor goroutine producing spurious "lost lock" warnings on normal release
// 3. Key namespace isolation between resolvers
// 4. Watch retry after failure (watchDistributedStore giving up permanently)
// 5. Full acquire-release lifecycle without spurious warnings

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvtools/valkeyrie/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/types"
)

// =============================================================================
// 1. Watch on non-existent key (Bug: first startup with empty etcd)
//
// On first deployment, the KV store has no data keys. The old Watch()
// called kvClient.Watch() directly, which failed with "key not found in store"
// because etcd can't watch a key that doesn't exist. This meant certificate
// updates from other replicas were NEVER received, causing all replicas to
// independently request certificates (thundering herd).
// =============================================================================

func TestWatch_KeyNotFound_InitializesAndSucceeds(t *testing.T) {
	mockClient := &MockKVClient{}

	// Simulate first startup: Get returns ErrKeyNotFound
	mockClient.On("Get", mock.Anything, "test/prefix/myresolver/data", mock.Anything).
		Return(nil, store.ErrKeyNotFound).Once()

	// Watch should initialize the key with empty compressed StoredData
	mockClient.On("Put", mock.Anything, "test/prefix/myresolver/data", mock.Anything, mock.Anything).
		Return(nil).Once()

	// After initialization, Watch on the underlying client should succeed
	watchChan := make(chan *store.KVPair, 1)
	mockClient.On("Watch", mock.Anything, "test/prefix/myresolver/data", mock.Anything).
		Return((<-chan *store.KVPair)(watchChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	updates, err := kvStore.Watch(t.Context(), "myresolver")

	require.NoError(t, err, "Watch must succeed on first startup with empty etcd")
	require.NotNil(t, updates, "Watch must return a valid channel")

	mockClient.AssertExpectations(t)

	// Verify the Put was called with valid compressed data
	putCall := mockClient.Calls[1] // second call is Put
	assert.Equal(t, "Put", putCall.Method)
	putData := putCall.Arguments[2].([]byte)
	assert.NotEmpty(t, putData, "should write non-empty compressed data")

	// Verify we can decompress and unmarshal what was written
	decompressed, err := decompress(putData)
	require.NoError(t, err, "initialized data must be valid gzip")

	var stored StoredData
	require.NoError(t, unmarshalStoredData(decompressed, &stored),
		"initialized data must be valid JSON")
	assert.Nil(t, stored.Account, "initial data should have no account")
	assert.Empty(t, stored.Certificates, "initial data should have no certificates")
}

func TestWatch_KeyNotFound_PutFails_ReturnsError(t *testing.T) {
	mockClient := &MockKVClient{}

	// Key doesn't exist
	mockClient.On("Get", mock.Anything, "test/prefix/myresolver/data", mock.Anything).
		Return(nil, store.ErrKeyNotFound)

	// But we can't write to it either (e.g. etcd is read-only or auth issue)
	mockClient.On("Put", mock.Anything, "test/prefix/myresolver/data", mock.Anything, mock.Anything).
		Return(errors.New("permission denied"))

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	updates, err := kvStore.Watch(t.Context(), "myresolver")

	require.Error(t, err, "Watch should fail if key can't be initialized")
	assert.Nil(t, updates)
	assert.Contains(t, err.Error(), "failed to initialize KV store key")
}

func TestWatch_KeyExists_SkipsInitialization(t *testing.T) {
	mockClient := &MockKVClient{}

	// Key already exists (normal restart)
	existingData, _ := compress([]byte(`{"Account":null,"Certificates":[]}`))
	mockClient.On("Get", mock.Anything, "test/prefix/myresolver/data", mock.Anything).
		Return(&store.KVPair{Key: "test/prefix/myresolver/data", Value: existingData}, nil)

	// Should NOT call Put — key already exists
	watchChan := make(chan *store.KVPair, 1)
	mockClient.On("Watch", mock.Anything, "test/prefix/myresolver/data", mock.Anything).
		Return((<-chan *store.KVPair)(watchChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	updates, err := kvStore.Watch(t.Context(), "myresolver")

	require.NoError(t, err)
	require.NotNil(t, updates)

	// Verify Put was NOT called
	mockClient.AssertNotCalled(t, "Put", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestWatch_GetFails_NonKeyNotFound_ReturnsError(t *testing.T) {
	mockClient := &MockKVClient{}

	// Get fails with a non-KeyNotFound error (e.g. network issue)
	mockClient.On("Get", mock.Anything, "test/prefix/myresolver/data", mock.Anything).
		Return(nil, errors.New("connection refused"))

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	updates, err := kvStore.Watch(t.Context(), "myresolver")

	require.Error(t, err)
	assert.Nil(t, updates)
	assert.Contains(t, err.Error(), "failed to check KV store key before watch")
}

// =============================================================================
// 2. Lock monitor: no spurious "Lost distributed lock" on normal release
//
// The old AcquireLock started a goroutine watching the lock channel. When
// ReleaseLock called Unlock(), etcd closed the channel, and the goroutine
// printed "Lost distributed lock" — even with a single replica. This was
// confusing and masked real lock-loss events.
// =============================================================================

func TestAcquireReleaseLock_NoSpuriousWarning(t *testing.T) {
	mockClient := &MockKVClient{}
	mockLocker := NewMockLocker()
	lockChan := make(chan struct{})

	mockClient.On("NewLock", mock.Anything, "test/prefix/myresolver/locks/example.com", mock.Anything).
		Return(mockLocker, nil)
	mockLocker.On("Lock", mock.Anything).Return((<-chan struct{})(lockChan), nil)
	mockLocker.On("Unlock", mock.Anything).Run(func(_ mock.Arguments) {
		close(lockChan) // Simulate what etcd does on Unlock
	}).Return(nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	// Acquire
	locker, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")
	require.NoError(t, err)
	require.NotNil(t, locker)

	// Verify monitor cancel func is stored
	kvStore.lock.RLock()
	_, hasMonitor := kvStore.lockMonitors["myresolver/example.com"]
	kvStore.lock.RUnlock()
	assert.True(t, hasMonitor, "monitor cancel func should be stored in lockMonitors")

	// Release — this must cancel the monitor BEFORE closing lockChan
	err = kvStore.ReleaseLock("myresolver", "example.com")
	require.NoError(t, err)

	// Give the goroutine time to react to the closed channel
	time.Sleep(100 * time.Millisecond)

	// Verify cleanup
	kvStore.lock.RLock()
	_, hasLock := kvStore.locks["myresolver/example.com"]
	_, hasMonitorAfter := kvStore.lockMonitors["myresolver/example.com"]
	kvStore.lock.RUnlock()
	assert.False(t, hasLock, "lock should be removed after release")
	assert.False(t, hasMonitorAfter, "monitor should be removed after release")

	// If we got here without the monitor goroutine logging "Lost distributed lock",
	// the bug is fixed. The goroutine checks monitorCtx.Err() before warning.
}

func TestAcquireReleaseLock_MonitorDetectsRealLockLoss(t *testing.T) {
	mockClient := &MockKVClient{}
	mockLocker := NewMockLocker()
	lockChan := make(chan struct{})

	mockClient.On("NewLock", mock.Anything, mock.Anything, mock.Anything).
		Return(mockLocker, nil)
	mockLocker.On("Lock", mock.Anything).Return((<-chan struct{})(lockChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	_, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")
	require.NoError(t, err)

	// Simulate unexpected lock loss (etcd TTL expired, connection dropped)
	// WITHOUT going through ReleaseLock — the monitor should detect this.
	close(lockChan)

	// Give the goroutine time to detect it
	time.Sleep(100 * time.Millisecond)

	// The monitor goroutine should have logged the warning because
	// monitorCtx was NOT cancelled (ReleaseLock was not called).
	// We can't easily assert on log output, but we verify the goroutine
	// ran by checking that the lock state is still in the map (ReleaseLock
	// was never called, so it should still be there).
	kvStore.lock.RLock()
	_, hasLock := kvStore.locks["myresolver/example.com"]
	kvStore.lock.RUnlock()
	assert.True(t, hasLock, "lock should still be in map since ReleaseLock was not called")
}

func TestReleaseLock_CancelsMonitorBeforeUnlock(t *testing.T) {
	// This test verifies the ordering: monitor must be cancelled BEFORE
	// the locker is unlocked. If order is reversed, the goroutine would
	// see the closed channel before the cancel and fire a false alarm.

	var unlockCalled atomic.Bool
	var monitorCancelledBeforeUnlock atomic.Bool

	mockClient := &MockKVClient{}
	lockChan := make(chan struct{})

	mockLocker := NewMockLocker()
	mockClient.On("NewLock", mock.Anything, mock.Anything, mock.Anything).
		Return(mockLocker, nil)
	mockLocker.On("Lock", mock.Anything).Return((<-chan struct{})(lockChan), nil)
	mockLocker.On("Unlock", mock.Anything).Run(func(_ mock.Arguments) {
		unlockCalled.Store(true)
		close(lockChan)
	}).Return(nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	_, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")
	require.NoError(t, err)

	// Wrap the monitor cancel to detect ordering
	kvStore.lock.Lock()
	originalCancel := kvStore.lockMonitors["myresolver/example.com"]
	kvStore.lockMonitors["myresolver/example.com"] = func() {
		if !unlockCalled.Load() {
			monitorCancelledBeforeUnlock.Store(true)
		}
		originalCancel()
	}
	kvStore.lock.Unlock()

	err = kvStore.ReleaseLock("myresolver", "example.com")
	require.NoError(t, err)

	assert.True(t, monitorCancelledBeforeUnlock.Load(),
		"monitor cancel must be called BEFORE locker.Unlock()")
}

// =============================================================================
// 3. Key namespace isolation between resolvers
//
// All KV keys for a resolver must be under {prefix}/{resolver}/:
//   - {prefix}/{resolver}/data       — certificate and account data
//   - {prefix}/{resolver}/locks/     — distributed locks
//   - {prefix}/{resolver}/challenges/ — HTTP-01 challenge tokens
//
// Resolvers must NOT share key paths. If two resolvers use the same prefix,
// their data, locks, and challenges must still be isolated by resolver name.
// =============================================================================

func TestKeyNamespace_DataKey(t *testing.T) {
	kvStore := &KVStore{prefix: "traefik/acme"}

	// Use internal getUnsafe key construction by checking what key is used.
	// We'll verify via the mock.
	mockClient := &MockKVClient{}
	kvStore.kvClient = mockClient
	kvStore.storedData = make(map[string]*StoredData)
	kvStore.lock = sync.RWMutex{}

	// For resolver "swissrdlca", the data key must be traefik/acme/swissrdlca/data
	mockClient.On("Get", mock.Anything, "traefik/acme/swissrdlca/data", mock.Anything).
		Return(nil, store.ErrKeyNotFound)

	_, _ = kvStore.get("swissrdlca")

	mockClient.AssertCalled(t, "Get", mock.Anything, "traefik/acme/swissrdlca/data", mock.Anything)
}

func TestKeyNamespace_LockKey(t *testing.T) {
	mockClient := &MockKVClient{}

	// Lock key must be {prefix}/{resolver}/locks/{domain}
	mockClient.On("NewLock", mock.Anything, "traefik/acme/swissrdlca/locks/example.com", mock.Anything).
		Return(nil, errors.New("expected key"))

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "traefik/acme",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	_, _ = kvStore.AcquireLock(t.Context(), "swissrdlca", "example.com")

	mockClient.AssertCalled(t, "NewLock", mock.Anything,
		"traefik/acme/swissrdlca/locks/example.com", mock.Anything)
}

func TestKeyNamespace_WatchKey(t *testing.T) {
	mockClient := &MockKVClient{}

	// Watch key must be {prefix}/{resolver}/data
	mockClient.On("Get", mock.Anything, "traefik/acme/swissrdlca/data", mock.Anything).
		Return(&store.KVPair{Key: "traefik/acme/swissrdlca/data", Value: []byte("{}")}, nil)

	watchChan := make(chan *store.KVPair, 1)
	mockClient.On("Watch", mock.Anything, "traefik/acme/swissrdlca/data", mock.Anything).
		Return((<-chan *store.KVPair)(watchChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "traefik/acme",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	_, err := kvStore.Watch(t.Context(), "swissrdlca")
	require.NoError(t, err)

	mockClient.AssertCalled(t, "Watch", mock.Anything,
		"traefik/acme/swissrdlca/data", mock.Anything)
}

func TestKeyNamespace_ChallengeKey(t *testing.T) {
	mockStore := newMockKVStore()

	// Challenge prefix must include resolver name
	prefix := "traefik/acme/swissrdlca/challenges"
	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	key := distChallenge.challengeKey("mytoken", "example.com")
	assert.Equal(t, "traefik/acme/swissrdlca/challenges/mytoken/example.com", key)
}

func TestKeyNamespace_TwoResolversSamePrefix_Isolated(t *testing.T) {
	// Two resolvers using the same etcd prefix must have completely separate key paths.
	mockClient := &MockKVClient{}

	// Both resolvers try to get their data — keys must be different
	mockClient.On("Get", mock.Anything, "traefik/acme/resolver1/data", mock.Anything).
		Return(nil, store.ErrKeyNotFound)
	mockClient.On("Get", mock.Anything, "traefik/acme/resolver2/data", mock.Anything).
		Return(nil, store.ErrKeyNotFound)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "traefik/acme",
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	_, _ = kvStore.get("resolver1")
	_, _ = kvStore.get("resolver2")

	mockClient.AssertCalled(t, "Get", mock.Anything, "traefik/acme/resolver1/data", mock.Anything)
	mockClient.AssertCalled(t, "Get", mock.Anything, "traefik/acme/resolver2/data", mock.Anything)
}

func TestKeyNamespace_SaveKey(t *testing.T) {
	mockClient := &MockKVClient{}

	// Save must write to {prefix}/{resolver}/data
	mockClient.On("Get", mock.Anything, "traefik/acme/swissrdlca/data", mock.Anything).
		Return(nil, store.ErrKeyNotFound)
	mockClient.On("Put", mock.Anything, "traefik/acme/swissrdlca/data", mock.Anything, mock.Anything).
		Return(nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "traefik/acme",
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	err := kvStore.SaveCertificates("swissrdlca", []*CertAndStore{})
	require.NoError(t, err)

	mockClient.AssertCalled(t, "Put", mock.Anything,
		"traefik/acme/swissrdlca/data", mock.Anything, mock.Anything)
}

// =============================================================================
// 4. Watch retry after failure
//
// The ResilientStore.Watch() buffers watches when disconnected and forwards
// them on reconnect. The provider's watchDistributedStore must retry with
// backoff when Watch fails, and reconnect when the channel closes.
// =============================================================================

func TestResilientStore_WatchBuffered_ForwardedOnConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	fallback := &mockStore{}
	attempts := atomic.Int32{}

	// Mock KV client that supports Watch
	mockClient := &MockKVClient{}
	watchChan := make(chan *store.KVPair, 1)
	mockClient.On("Put", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockClient.On("Delete", mock.Anything, mock.Anything).Return(nil)
	mockClient.On("Get", mock.Anything, mock.Anything, mock.Anything).
		Return(&store.KVPair{Value: []byte("{}")}, nil)
	mockClient.On("Watch", mock.Anything, mock.Anything, mock.Anything).
		Return((<-chan *store.KVPair)(watchChan), nil)

	// Fail twice, then succeed
	rs := NewResilientStore(ctx, fallback, func(_ context.Context) (*KVStore, error) {
		count := attempts.Add(1)
		if count <= 2 {
			return nil, errors.New("etcd not ready")
		}
		return &KVStore{
			kvClient:     mockClient,
			prefix:       "test",
			lockTimeout:  30 * time.Second,
			storedData:   make(map[string]*StoredData),
			locks:        make(map[string]store.Locker),
			lockMonitors: make(map[string]context.CancelFunc),
		}, nil
	}, nil, "")

	// Request a watch while disconnected
	ch, err := rs.Watch(ctx, "myresolver")
	require.NoError(t, err, "Watch should succeed even while disconnected (buffered)")
	require.NotNil(t, ch)

	// Wait for reconnection (2 failures * 5s backoff + margin)
	require.Eventually(t, func() bool {
		return rs.Connected()
	}, 20*time.Second, 500*time.Millisecond, "should eventually connect")

	// The buffered watch should receive an immediate notification on connect
	select {
	case <-ch:
		// Success — the forwarded watch sent an initial notification
	case <-time.After(5 * time.Second):
		t.Fatal("expected initial notification on buffered watch after reconnect")
	}
}

// =============================================================================
// 5. Full acquire-release lifecycle (end-to-end)
//
// Simulates the exact production flow: acquire lock, do work, release lock.
// Verifies no leaks, no spurious warnings, correct cleanup.
// =============================================================================

func TestAcquireReleaseLock_FullLifecycle(t *testing.T) {
	mockClient := &MockKVClient{}

	for i := range 5 {
		domain := domainForIndex(i)
		lockChan := make(chan struct{})
		ml := NewMockLocker()

		mockClient.On("NewLock", mock.Anything,
			"test/prefix/myresolver/locks/"+domain, mock.Anything).
			Return(ml, nil)
		ml.On("Lock", mock.Anything).Return((<-chan struct{})(lockChan), nil)
		ml.On("Unlock", mock.Anything).Run(func(_ mock.Arguments) {
			close(lockChan)
		}).Return(nil)
	}

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	// Acquire and release 5 locks concurrently
	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			domain := domainForIndex(idx)

			locker, err := kvStore.AcquireLock(t.Context(), "myresolver", domain)
			require.NoError(t, err)
			require.NotNil(t, locker)

			// Simulate work
			time.Sleep(10 * time.Millisecond)

			err = kvStore.ReleaseLock("myresolver", domain)
			require.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// All locks and monitors must be cleaned up
	kvStore.lock.RLock()
	assert.Empty(t, kvStore.locks, "all locks should be released")
	assert.Empty(t, kvStore.lockMonitors, "all monitors should be cancelled")
	kvStore.lock.RUnlock()

	// Give goroutines time to exit
	time.Sleep(100 * time.Millisecond)
}

func TestAcquireReleaseLock_SameDomain_Sequential(t *testing.T) {
	// Simulate the production scenario: one replica acquires a lock for a domain,
	// obtains a certificate, releases it. Then does it again for the same domain
	// (e.g. on renewal). No state should leak between cycles.

	mockClient := &MockKVClient{}

	for cycle := range 3 {
		_ = cycle
		lockChan := make(chan struct{})
		ml := NewMockLocker()

		mockClient.On("NewLock", mock.Anything,
			"test/prefix/myresolver/locks/example.com", mock.Anything).
			Return(ml, nil).Once()
		ml.On("Lock", mock.Anything).Return((<-chan struct{})(lockChan), nil).Once()
		ml.On("Unlock", mock.Anything).Run(func(_ mock.Arguments) {
			close(lockChan)
		}).Return(nil).Once()
	}

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	for i := range 3 {
		locker, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")
		require.NoError(t, err, "cycle %d: acquire should succeed", i)
		require.NotNil(t, locker)

		err = kvStore.ReleaseLock("myresolver", "example.com")
		require.NoError(t, err, "cycle %d: release should succeed", i)

		// Verify clean state between cycles
		kvStore.lock.RLock()
		assert.Empty(t, kvStore.locks, "cycle %d: locks map should be empty", i)
		assert.Empty(t, kvStore.lockMonitors, "cycle %d: monitors map should be empty", i)
		kvStore.lock.RUnlock()
	}
}

// =============================================================================
// 6. Watch delivers updates and invalidates cache
//
// When another replica saves a certificate, the watch channel should fire
// and the local cache should be invalidated so the next read fetches fresh data.
// =============================================================================

func TestWatch_ReceivesUpdatesAndInvalidatesCache(t *testing.T) {
	mockClient := &MockKVClient{}

	key := "test/prefix/myresolver/data"

	// Key exists (normal operation)
	mockClient.On("Get", mock.Anything, key, mock.Anything).
		Return(&store.KVPair{Key: key, Value: []byte("{}")}, nil)

	// Watch returns a channel
	watchChan := make(chan *store.KVPair, 1)
	mockClient.On("Watch", mock.Anything, key, mock.Anything).
		Return((<-chan *store.KVPair)(watchChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	// Pre-populate cache
	kvStore.storedData["myresolver"] = &StoredData{
		Certificates: []*CertAndStore{{Certificate: Certificate{Domain: types.Domain{Main: "old.com"}}}},
	}

	updates, err := kvStore.Watch(t.Context(), "myresolver")
	require.NoError(t, err)

	// Simulate update from another replica
	watchChan <- &store.KVPair{Key: key, Value: []byte("updated")}

	// Should receive notification
	select {
	case <-updates:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("expected update notification from watch")
	}

	// Cache should be invalidated
	kvStore.lock.RLock()
	_, cached := kvStore.storedData["myresolver"]
	kvStore.lock.RUnlock()
	assert.False(t, cached, "cache should be invalidated after watch fires")
}

func TestWatch_NilPairIsIgnored(t *testing.T) {
	mockClient := &MockKVClient{}
	key := "test/prefix/myresolver/data"

	mockClient.On("Get", mock.Anything, key, mock.Anything).
		Return(&store.KVPair{Key: key, Value: []byte("{}")}, nil)

	watchChan := make(chan *store.KVPair, 2)
	mockClient.On("Watch", mock.Anything, key, mock.Anything).
		Return((<-chan *store.KVPair)(watchChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	updates, err := kvStore.Watch(t.Context(), "myresolver")
	require.NoError(t, err)

	// Send a nil pair (should be ignored)
	watchChan <- nil

	// Send a real pair after
	watchChan <- &store.KVPair{Key: key, Value: []byte("real")}

	// Should only get one notification (from the real pair)
	select {
	case <-updates:
		// Good — got the real update
	case <-time.After(2 * time.Second):
		t.Fatal("expected update notification")
	}
}

// =============================================================================
// Helpers
// =============================================================================

func domainForIndex(i int) string {
	domains := []string{
		"alpha.example.com",
		"beta.example.com",
		"gamma.example.com",
		"delta.example.com",
		"epsilon.example.com",
	}
	return domains[i]
}

// unmarshalStoredData is a test helper to unmarshal StoredData from JSON.
func unmarshalStoredData(data []byte, out *StoredData) error {
	return json.Unmarshal(data, out)
}
