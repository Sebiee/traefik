package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kvtools/etcdv3"
	"github.com/traefik/traefik/v3/pkg/types"
)

// EtcdStoreConfig holds etcd-specific settings for ACME storage.
type EtcdStoreConfig struct {
	Endpoints   []string         `description:"etcd endpoints." json:"endpoints,omitempty" toml:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	Username    string           `description:"Username for etcd authentication." json:"username,omitempty" toml:"username,omitempty" yaml:"username,omitempty" loggable:"false"`
	Password    string           `description:"Password for etcd authentication." json:"password,omitempty" toml:"password,omitempty" yaml:"password,omitempty" loggable:"false"`
	Prefix      string           `description:"Key prefix for ACME data." json:"prefix,omitempty" toml:"prefix,omitempty" yaml:"prefix,omitempty"`
	TLS         *types.ClientTLS `description:"TLS configuration for etcd connection." json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty"`
	LockTimeout time.Duration    `description:"Lock timeout for certificate operations." json:"lockTimeout,omitempty" toml:"lockTimeout,omitempty" yaml:"lockTimeout,omitempty"`
}

// SetDefaults sets the default values for EtcdStoreConfig.
func (c *EtcdStoreConfig) SetDefaults() {
	c.Endpoints = []string{"127.0.0.1:2379"}
	c.Prefix = DefaultPrefix
	c.LockTimeout = 30 * time.Second
}

// NewEtcdStore creates a new KVStore using etcd as the backend.
func NewEtcdStore(ctx context.Context, config *EtcdStoreConfig) (*KVStore, error) {
	if config == nil {
		return nil, errors.New("etcd configuration is required")
	}

	etcdConfig := &etcdv3.Config{
		ConnectionTimeout: 3 * time.Second,
		Username:          config.Username,
		Password:          config.Password,
	}

	if config.TLS != nil {
		tlsConfig, err := config.TLS.CreateTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configuration: %w", err)
		}
		etcdConfig.TLS = tlsConfig
	}

	kvConfig := &KVStoreConfig{
		Endpoints:   config.Endpoints,
		Prefix:      config.Prefix,
		LockTimeout: config.LockTimeout,
	}

	return NewKVStore(ctx, etcdv3.StoreName, etcdConfig, kvConfig)
}
