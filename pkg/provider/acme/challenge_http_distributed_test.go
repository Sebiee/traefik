package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/kvtools/valkeyrie/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKVStore is a simple in-memory KV store for testing.
type mockKVStore struct {
	data map[string][]byte
	mu   sync.RWMutex
}

func newMockKVStore() *mockKVStore {
	return &mockKVStore{
		data: make(map[string][]byte),
	}
}

func (m *mockKVStore) Put(ctx context.Context, key string, value []byte, opts *store.WriteOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockKVStore) Get(ctx context.Context, key string, opts *store.ReadOptions) (*store.KVPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if val, ok := m.data[key]; ok {
		return &store.KVPair{Key: key, Value: val}, nil
	}
	return nil, store.ErrKeyNotFound
}

func (m *mockKVStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *mockKVStore) Exists(ctx context.Context, key string, opts *store.ReadOptions) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockKVStore) Watch(ctx context.Context, key string, opts *store.ReadOptions) (<-chan *store.KVPair, error) {
	return nil, nil
}

func (m *mockKVStore) WatchTree(ctx context.Context, directory string, opts *store.ReadOptions) (<-chan []*store.KVPair, error) {
	return nil, nil
}

func (m *mockKVStore) NewLock(ctx context.Context, key string, opts *store.LockOptions) (store.Locker, error) {
	return nil, nil
}

func (m *mockKVStore) List(ctx context.Context, directory string, opts *store.ReadOptions) ([]*store.KVPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var pairs []*store.KVPair
	for k, v := range m.data {
		if len(k) >= len(directory) && k[:len(directory)] == directory {
			pairs = append(pairs, &store.KVPair{Key: k, Value: v})
		}
	}
	return pairs, nil
}

func (m *mockKVStore) DeleteTree(ctx context.Context, directory string) error {
	return nil
}

func (m *mockKVStore) AtomicPut(ctx context.Context, key string, value []byte, previous *store.KVPair, opts *store.WriteOptions) (bool, *store.KVPair, error) {
	return true, nil, nil
}

func (m *mockKVStore) AtomicDelete(ctx context.Context, key string, previous *store.KVPair) (bool, error) {
	return true, nil
}

func (m *mockKVStore) Close() error {
	return nil
}

func TestDistributedChallengeHTTP_PresentAndServe(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	domain := "example.com"
	token := "test-token-123"
	keyAuth := "keyAuth-secret-value"

	// Present the challenge
	err := distChallenge.Present(domain, token, keyAuth)
	require.NoError(t, err)

	// Verify it's stored in KV store with correct key
	expectedKey := prefix + "/" + token + "/" + domain
	pair, err := mockStore.Get(t.Context(), expectedKey, nil)
	require.NoError(t, err)
	require.NotNil(t, pair)

	var data ChallengeData
	err = json.Unmarshal(pair.Value, &data)
	require.NoError(t, err)
	assert.Equal(t, domain, data.Domain)
	assert.Equal(t, token, data.Token)
	assert.Equal(t, keyAuth, data.KeyAuth)

	// Verify it's also in local cache
	distChallenge.lock.RLock()
	cachedValue, ok := distChallenge.localCache[token][domain]
	distChallenge.lock.RUnlock()
	assert.True(t, ok)
	assert.Equal(t, keyAuth, string(cachedValue))

	// Test ServeHTTP
	challengePath := http01.ChallengePath(token)
	req := httptest.NewRequest(http.MethodGet, challengePath, nil)
	req.Host = domain

	rw := httptest.NewRecorder()
	distChallenge.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, keyAuth, rw.Body.String())
}

func TestDistributedChallengeHTTP_ServeHTTPFromKVStore(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	// Create a challenge directly in the KV store (simulating another replica)
	domain := "other-replica.com"
	token := "remote-token-456"
	keyAuth := "remote-keyAuth-value"

	key := prefix + "/" + token + "/" + domain
	data := ChallengeData{
		Domain:  domain,
		Token:   token,
		KeyAuth: keyAuth,
	}
	value, err := json.Marshal(data)
	require.NoError(t, err)
	_ = mockStore.Put(t.Context(), key, value, nil)

	// Create a new DistributedChallengeHTTP that doesn't have this in local cache
	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	// Test ServeHTTP - should fetch from KV store
	challengePath := http01.ChallengePath(token)
	req := httptest.NewRequest(http.MethodGet, challengePath, nil)
	req.Host = domain

	rw := httptest.NewRecorder()
	distChallenge.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, keyAuth, rw.Body.String())
}

func TestDistributedChallengeHTTP_CleanUp(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	domain := "cleanup.example.com"
	token := "cleanup-token"
	keyAuth := "cleanup-keyAuth"

	// Present the challenge
	err := distChallenge.Present(domain, token, keyAuth)
	require.NoError(t, err)

	// Verify it exists
	key := prefix + "/" + token + "/" + domain
	_, err = mockStore.Get(t.Context(), key, nil)
	require.NoError(t, err)

	// Clean up
	err = distChallenge.CleanUp(domain, token, keyAuth)
	require.NoError(t, err)

	// Verify it's removed from KV store
	_, err = mockStore.Get(t.Context(), key, nil)
	assert.ErrorIs(t, err, store.ErrKeyNotFound)

	// Verify it's removed from local cache
	distChallenge.lock.RLock()
	_, ok := distChallenge.localCache[token]
	distChallenge.lock.RUnlock()
	assert.False(t, ok)
}

func TestDistributedChallengeHTTP_ServeHTTPNotFound(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	// Test with non-existent token
	challengePath := http01.ChallengePath("nonexistent-token")
	req := httptest.NewRequest(http.MethodGet, challengePath, nil)
	req.Host = "example.com"

	rw := httptest.NewRecorder()
	distChallenge.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusNotFound, rw.Code)
}

func TestDistributedChallengeHTTP_ServeHTTPWithHostPort(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	domain := "hostport.example.com"
	token := "hostport-token"
	keyAuth := "hostport-keyAuth"

	err := distChallenge.Present(domain, token, keyAuth)
	require.NoError(t, err)

	// Test with host:port format
	challengePath := http01.ChallengePath(token)
	req := httptest.NewRequest(http.MethodGet, challengePath, nil)
	req.Host = domain + ":8080"

	rw := httptest.NewRecorder()
	distChallenge.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, keyAuth, rw.Body.String())
}

func TestDistributedChallengeHTTP_Timeout(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	timeout, interval := distChallenge.Timeout()
	assert.Equal(t, 60*time.Second, timeout)
	assert.Equal(t, 5*time.Second, interval)
}

func TestDistributedChallengeHTTP_ThreadSafety(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			domain := "concurrent" + string(rune('0'+i)) + ".example.com"
			token := "concurrent-token-" + string(rune('0'+i))
			keyAuth := "concurrent-keyAuth-" + string(rune('0'+i))

			err := distChallenge.Present(domain, token, keyAuth)
			assert.NoError(t, err)

			// Serve the challenge
			challengePath := http01.ChallengePath(token)
			req := httptest.NewRequest(http.MethodGet, challengePath, nil)
			req.Host = domain

			rw := httptest.NewRecorder()
			distChallenge.ServeHTTP(rw, req)
			assert.Equal(t, http.StatusOK, rw.Code)

			err = distChallenge.CleanUp(domain, token, keyAuth)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
}

func TestChallengeKey(t *testing.T) {
	mockStore := newMockKVStore()
	prefix := "traefik/acme/myresolver/challenges"

	distChallenge := NewDistributedChallengeHTTP(mockStore, prefix)

	// Verify the challenge key is correctly namespaced under the resolver
	key := distChallenge.challengeKey("mytoken", "example.com")
	expected := "traefik/acme/myresolver/challenges/mytoken/example.com"
	assert.Equal(t, expected, key)

	// Ensure there's no double challenges in the path
	assert.NotContains(t, key, "challenges/challenges")
}
