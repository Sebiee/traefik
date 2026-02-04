package acme

import (
	"context"

	"github.com/kvtools/valkeyrie/store"
)

// StoredData represents the data managed by Store.
type StoredData struct {
	Account      *Account        `json:"Account"`
	Certificates []*CertAndStore `json:"Certificates"`
}

// Store is a generic interface that represents a storage.
type Store interface {
	GetAccount(resolverName string) (*Account, error)
	SaveAccount(resolverName string, account *Account) error
	GetCertificates(resolverName string) ([]*CertAndStore, error)
	SaveCertificates(resolverName string, certificates []*CertAndStore) error
}

// DistributedStore extends Store with distributed locking for multi-replica deployments.
type DistributedStore interface {
	Store

	// AcquireLock acquires a distributed lock for certificate operations on a domain.
	AcquireLock(ctx context.Context, resolverName, domain string) (store.Locker, error)

	// ReleaseLock releases the distributed lock.
	ReleaseLock(resolverName, domain string) error

	// Watch subscribes to certificate updates from other replicas.
	Watch(ctx context.Context, resolverName string) (<-chan struct{}, error)

	// GetCertificatesFresh fetches certificates bypassing cache.
	GetCertificatesFresh(resolverName string) ([]*CertAndStore, error)
}
