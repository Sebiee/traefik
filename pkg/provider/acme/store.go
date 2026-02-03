package acme

import (
	"context"

	"github.com/kvtools/valkeyrie/store"
)

// StoredData represents the data managed by Store.
type StoredData struct {
	Account      *Account
	Certificates []*CertAndStore
}

// Store is a generic interface that represents a storage.
type Store interface {
	GetAccount(resolverName string) (*Account, error)
	SaveAccount(resolverName string, account *Account) error
	GetCertificates(resolverName string) ([]*CertAndStore, error)
	SaveCertificates(resolverName string, certificates []*CertAndStore) error
}

// DistributedStore extends Store with distributed locking capabilities.
// This interface is implemented by KV store backends (Redis, Consul, etcd)
// to enable multiple Traefik replicas to safely share ACME certificates.
type DistributedStore interface {
	Store

	// AcquireLock attempts to acquire a distributed lock for the given domain.
	// This prevents multiple Traefik instances from simultaneously requesting
	// certificates for the same domain.
	AcquireLock(ctx context.Context, domain string) (store.Locker, error)

	// ReleaseLock releases the distributed lock for the given domain.
	ReleaseLock(domain string) error

	// Watch sets up a watch on the store for certificate updates.
	// This allows Traefik instances to sync certificate updates from other instances.
	Watch(ctx context.Context, resolverName string) (<-chan struct{}, error)
}
