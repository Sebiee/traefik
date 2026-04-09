package acme

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kvtools/valkeyrie/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestKVStoreConfig_SetDefaults(t *testing.T) {
	config := &KVStoreConfig{}
	config.SetDefaults()

	assert.Equal(t, "traefik/acme", config.Prefix)
	assert.Equal(t, 30*time.Second, config.LockTimeout)
}

func TestEtcdStoreConfig_SetDefaults(t *testing.T) {
	config := &EtcdStoreConfig{}
	config.SetDefaults()

	assert.Equal(t, []string{"127.0.0.1:2379"}, config.Endpoints)
	assert.Equal(t, "traefik/acme", config.Prefix)
	assert.Equal(t, 30*time.Second, config.LockTimeout)
}

func TestCompress(t *testing.T) {
	testData := []byte(`{"Account":{"Email":"test@example.com"},"Certificates":[]}`)

	compressed, err := compress(testData)
	assert.NoError(t, err)
	assert.NotEmpty(t, compressed)

	// Compressed data should be different from original
	assert.NotEqual(t, testData, compressed)

	// Decompress should restore original
	decompressed, err := decompress(compressed)
	assert.NoError(t, err)
	assert.Equal(t, testData, decompressed)
}

func TestDecompress_InvalidData(t *testing.T) {
	// Invalid gzip data
	_, err := decompress([]byte("not gzip data"))
	assert.Error(t, err)
}

// MockLocker is a mock implementation of store.Locker for testing.
type MockLocker struct {
	mock.Mock

	lockChan chan struct{}
}

func NewMockLocker() *MockLocker {
	return &MockLocker{
		lockChan: make(chan struct{}),
	}
}

func (m *MockLocker) Lock(ctx context.Context) (<-chan struct{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(<-chan struct{}), args.Error(1)
}

func (m *MockLocker) Unlock(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockKVClient is a mock implementation of store.Store for testing.
type MockKVClient struct {
	mock.Mock
}

func (m *MockKVClient) Put(ctx context.Context, key string, value []byte, opts *store.WriteOptions) error {
	args := m.Called(ctx, key, value, opts)
	return args.Error(0)
}

func (m *MockKVClient) Get(ctx context.Context, key string, opts *store.ReadOptions) (*store.KVPair, error) {
	args := m.Called(ctx, key, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*store.KVPair), args.Error(1)
}

func (m *MockKVClient) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockKVClient) Exists(ctx context.Context, key string, opts *store.ReadOptions) (bool, error) {
	args := m.Called(ctx, key, opts)
	return args.Bool(0), args.Error(1)
}

func (m *MockKVClient) Watch(ctx context.Context, key string, opts *store.ReadOptions) (<-chan *store.KVPair, error) {
	args := m.Called(ctx, key, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(<-chan *store.KVPair), args.Error(1)
}

func (m *MockKVClient) WatchTree(ctx context.Context, directory string, opts *store.ReadOptions) (<-chan []*store.KVPair, error) {
	args := m.Called(ctx, directory, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(<-chan []*store.KVPair), args.Error(1)
}

func (m *MockKVClient) NewLock(ctx context.Context, key string, opts *store.LockOptions) (store.Locker, error) {
	args := m.Called(ctx, key, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(store.Locker), args.Error(1)
}

func (m *MockKVClient) List(ctx context.Context, directory string, opts *store.ReadOptions) ([]*store.KVPair, error) {
	args := m.Called(ctx, directory, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*store.KVPair), args.Error(1)
}

func (m *MockKVClient) DeleteTree(ctx context.Context, directory string) error {
	args := m.Called(ctx, directory)
	return args.Error(0)
}

func (m *MockKVClient) AtomicPut(ctx context.Context, key string, value []byte, previous *store.KVPair, opts *store.WriteOptions) (bool, *store.KVPair, error) {
	args := m.Called(ctx, key, value, previous, opts)
	if args.Get(1) == nil {
		return args.Bool(0), nil, args.Error(2)
	}
	return args.Bool(0), args.Get(1).(*store.KVPair), args.Error(2)
}

func (m *MockKVClient) AtomicDelete(ctx context.Context, key string, previous *store.KVPair) (bool, error) {
	args := m.Called(ctx, key, previous)
	return args.Bool(0), args.Error(1)
}

func (m *MockKVClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestKVStore_AcquireLock_Success(t *testing.T) {
	mockClient := &MockKVClient{}
	mockLocker := NewMockLocker()

	lockChan := make(chan struct{})
	mockClient.On("NewLock", mock.Anything, "test/prefix/myresolver/locks/example.com", mock.Anything).Return(mockLocker, nil)
	mockLocker.On("Lock", mock.Anything).Return((<-chan struct{})(lockChan), nil)

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	locker, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")

	require.NoError(t, err)
	assert.NotNil(t, locker)
	mockClient.AssertExpectations(t)
	mockLocker.AssertExpectations(t)
}

func TestKVStore_AcquireLock_Failure(t *testing.T) {
	mockClient := &MockKVClient{}

	mockClient.On("NewLock", mock.Anything, "test/prefix/myresolver/locks/example.com", mock.Anything).
		Return(nil, errors.New("connection refused"))

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	locker, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")

	require.Error(t, err)
	assert.Nil(t, locker)
	assert.Contains(t, err.Error(), "failed to create lock")
	mockClient.AssertExpectations(t)
}

func TestKVStore_AcquireLock_LockContention(t *testing.T) {
	mockClient := &MockKVClient{}
	mockLocker := NewMockLocker()

	mockClient.On("NewLock", mock.Anything, "test/prefix/myresolver/locks/example.com", mock.Anything).Return(mockLocker, nil)
	mockLocker.On("Lock", mock.Anything).Return(nil, errors.New("lock already held"))

	kvStore := &KVStore{
		kvClient:     mockClient,
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
	}

	locker, err := kvStore.AcquireLock(t.Context(), "myresolver", "example.com")

	require.Error(t, err)
	assert.Nil(t, locker)
	assert.Contains(t, err.Error(), "failed to acquire lock")
	mockClient.AssertExpectations(t)
	mockLocker.AssertExpectations(t)
}

func TestKVStore_ReleaseLock_Success(t *testing.T) {
	mockLocker := NewMockLocker()
	mockLocker.On("Unlock", mock.Anything).Return(nil)

	kvStore := &KVStore{
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
		lock:         sync.RWMutex{},
	}

	// Add a lock to release (key is resolver/domain)
	kvStore.locks["myresolver/example.com"] = mockLocker

	err := kvStore.ReleaseLock("myresolver", "example.com")

	require.NoError(t, err)
	assert.Empty(t, kvStore.locks)
	mockLocker.AssertExpectations(t)
}

func TestKVStore_ReleaseLock_NoExistingLock(t *testing.T) {
	kvStore := &KVStore{
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
		lock:         sync.RWMutex{},
	}

	// No lock exists - should return nil (graceful handling)
	err := kvStore.ReleaseLock("myresolver", "nonexistent.com")

	require.NoError(t, err)
}

func TestKVStore_ReleaseLock_UnlockFailure(t *testing.T) {
	mockLocker := NewMockLocker()
	mockLocker.On("Unlock", mock.Anything).Return(errors.New("unlock failed"))

	kvStore := &KVStore{
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
		lock:         sync.RWMutex{},
	}

	// Add a lock to release (key is resolver/domain)
	kvStore.locks["myresolver/example.com"] = mockLocker

	err := kvStore.ReleaseLock("myresolver", "example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to release lock")
	// Lock should still be removed from the map even if unlock fails
	assert.Empty(t, kvStore.locks)
	mockLocker.AssertExpectations(t)
}

func TestKVStore_DoubleReleaseLock_Idempotent(t *testing.T) {
	mockLocker := NewMockLocker()
	mockLocker.On("Unlock", mock.Anything).Return(nil).Once()

	kvStore := &KVStore{
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
		lock:         sync.RWMutex{},
	}

	// Add a lock to release (key is resolver/domain)
	kvStore.locks["myresolver/example.com"] = mockLocker

	// First release should succeed
	err := kvStore.ReleaseLock("myresolver", "example.com")
	require.NoError(t, err)

	// Second release should be idempotent (no error)
	err = kvStore.ReleaseLock("myresolver", "example.com")
	require.NoError(t, err)

	mockLocker.AssertExpectations(t)
}

func TestKVStore_LockTimeout_Configuration(t *testing.T) {
	testCases := []struct {
		desc        string
		lockTimeout time.Duration
	}{
		{
			desc:        "default timeout",
			lockTimeout: 30 * time.Second,
		},
		{
			desc:        "custom short timeout",
			lockTimeout: 5 * time.Second,
		},
		{
			desc:        "custom long timeout",
			lockTimeout: 2 * time.Minute,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			kvStore := &KVStore{
				lockTimeout: test.lockTimeout,
			}

			assert.Equal(t, test.lockTimeout, kvStore.lockTimeout)
		})
	}
}

func TestKVStore_ConcurrentLockOperations(t *testing.T) {
	kvStore := &KVStore{
		prefix:       "test/prefix",
		lockTimeout:  30 * time.Second,
		storedData:   make(map[string]*StoredData),
		locks:        make(map[string]store.Locker),
		lockMonitors: make(map[string]context.CancelFunc),
		lock:         sync.RWMutex{},
	}

	// Test concurrent release lock operations don't panic
	var wg sync.WaitGroup
	domains := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

	// Add mock lockers (key is resolver/domain)
	for _, domain := range domains {
		mockLocker := NewMockLocker()
		mockLocker.On("Unlock", mock.Anything).Return(nil)
		kvStore.locks["myresolver/"+domain] = mockLocker
	}

	// Release locks concurrently
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			_ = kvStore.ReleaseLock("myresolver", d)
		}(domain)
	}

	wg.Wait()

	// All locks should be released
	assert.Empty(t, kvStore.locks)
}
