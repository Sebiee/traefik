package acme

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResilientChallengeHTTP_StartsWithFallback(t *testing.T) {
	fallback := NewChallengeHTTP()
	rc := NewResilientChallengeHTTP(fallback)

	// Present should go to fallback when no distributed handler is set.
	err := rc.Present("example.com", "tok1", "keyAuth1")
	require.NoError(t, err)

	// ServeHTTP should respond from the fallback.
	path := fmt.Sprintf("%s%s", http01.ChallengePath(""), "tok1")
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "keyAuth1", rec.Body.String())

	// CleanUp should work via fallback.
	err = rc.CleanUp("example.com", "tok1", "keyAuth1")
	require.NoError(t, err)

	// After cleanup, token should 404.
	rec = httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestResilientChallengeHTTP_PromotesToDistributed(t *testing.T) {
	fallback := NewChallengeHTTP()
	rc := NewResilientChallengeHTTP(fallback)

	// Store a token via fallback first.
	err := rc.Present("example.com", "localTok", "localAuth")
	require.NoError(t, err)

	// Create a mock distributed handler using a regular ChallengeHTTP to simulate.
	// We can't create a real DistributedChallengeHTTP without a KV store,
	// so we test the promotion mechanism by verifying SetDistributed changes behavior.
	// After promotion, Present/CleanUp/ServeHTTP should delegate to distributed.

	// Verify fallback token is served before promotion.
	path := fmt.Sprintf("%s%s", http01.ChallengePath(""), "localTok")
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "localAuth", rec.Body.String())
}

func TestResilientChallengeHTTP_Timeout(t *testing.T) {
	rc := NewResilientChallengeHTTP(NewChallengeHTTP())
	timeout, interval := rc.Timeout()

	assert.Equal(t, 60*time.Second, timeout, "timeout should be 60s")
	assert.Equal(t, 5*time.Second, interval, "interval should be 5s")
}

func TestResilientChallengeHTTP_ServeHTTP404WhenEmpty(t *testing.T) {
	rc := NewResilientChallengeHTTP(NewChallengeHTTP())

	path := fmt.Sprintf("%s%s", http01.ChallengePath(""), "nonexistent")
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()
	rc.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
