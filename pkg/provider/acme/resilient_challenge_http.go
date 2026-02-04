package acme

import (
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
)

// ResilientChallengeHTTP wraps a local ChallengeHTTP and transparently promotes
// to a DistributedChallengeHTTP once the KV backend becomes available.
//
// While disconnected, cert issuance is blocked by ResilientStore.AcquireLock
// returning an error, so Present/CleanUp are effectively never called.
// ServeHTTP delegates to whichever implementation is active (local or distributed).
type ResilientChallengeHTTP struct {
	mu          sync.RWMutex
	fallback    *ChallengeHTTP
	distributed *DistributedChallengeHTTP
}

// NewResilientChallengeHTTP creates a challenge handler that starts with
// the local fallback and can be promoted to distributed mode.
func NewResilientChallengeHTTP(fallback *ChallengeHTTP) *ResilientChallengeHTTP {
	return &ResilientChallengeHTTP{fallback: fallback}
}

// SetDistributed atomically promotes this handler to distributed mode.
// Called by ResilientStore once the KV backend connects.
func (r *ResilientChallengeHTTP) SetDistributed(d *DistributedChallengeHTTP) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.distributed = d

	log.Info().Str(logs.ProviderName, "acme").
		Msg("HTTP challenge handler promoted to distributed mode")
}

// Present stores the ACME challenge token.
func (r *ResilientChallengeHTTP) Present(domain, token, keyAuth string) error {
	r.mu.RLock()
	d := r.distributed
	r.mu.RUnlock()
	if d != nil {
		return d.Present(domain, token, keyAuth)
	}
	return r.fallback.Present(domain, token, keyAuth)
}

// CleanUp removes the ACME challenge token.
func (r *ResilientChallengeHTTP) CleanUp(domain, token, keyAuth string) error {
	r.mu.RLock()
	d := r.distributed
	r.mu.RUnlock()
	if d != nil {
		return d.CleanUp(domain, token, keyAuth)
	}
	return r.fallback.CleanUp(domain, token, keyAuth)
}

// Timeout returns the challenge resolution timeout and polling interval.
func (r *ResilientChallengeHTTP) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Second, 5 * time.Second
}

// ServeHTTP handles incoming ACME HTTP-01 challenge verification requests.
func (r *ResilientChallengeHTTP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	d := r.distributed
	r.mu.RUnlock()
	if d != nil {
		d.ServeHTTP(rw, req)
		return
	}
	r.fallback.ServeHTTP(rw, req)
}
