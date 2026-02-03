package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kvtools/consul"
	"github.com/traefik/traefik/v3/pkg/types"
)

// ConsulStoreConfig holds the Consul-specific configuration for ACME storage.
type ConsulStoreConfig struct {
	// Endpoints is the list of Consul endpoints.
	Endpoints []string `description:"Consul endpoints." json:"endpoints,omitempty" toml:"endpoints,omitempty" yaml:"endpoints,omitempty"`

	// Token is the ACL token for Consul.
	Token string `description:"ACL token for Consul authentication." json:"token,omitempty" toml:"token,omitempty" yaml:"token,omitempty" loggable:"false"`

	// Namespace is the Consul namespace (Enterprise only).
	Namespace string `description:"Consul namespace (Enterprise only)." json:"namespace,omitempty" toml:"namespace,omitempty" yaml:"namespace,omitempty"`

	// Prefix is the key prefix for ACME data.
	Prefix string `description:"Key prefix for ACME data." json:"prefix,omitempty" toml:"prefix,omitempty" yaml:"prefix,omitempty"`

	// TLS configuration.
	TLS *types.ClientTLS `description:"TLS configuration for Consul connection." json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty"`

	// LockTimeout is the timeout for distributed locks.
	LockTimeout time.Duration `description:"Lock timeout for certificate operations." json:"lockTimeout,omitempty" toml:"lockTimeout,omitempty" yaml:"lockTimeout,omitempty"`
}

// SetDefaults sets the default values for ConsulStoreConfig.
func (c *ConsulStoreConfig) SetDefaults() {
	c.Endpoints = []string{"127.0.0.1:8500"}
	c.Prefix = DefaultPrefix
	c.LockTimeout = 30 * time.Second
}

// NewConsulStore creates a new KVStore using Consul as the backend.
func NewConsulStore(ctx context.Context, config *ConsulStoreConfig) (*KVStore, error) {
	if config == nil {
		return nil, errors.New("consul configuration is required")
	}

	// Wildcard namespace is not supported
	if config.Namespace == "*" {
		return nil, errors.New("wildcard namespace is not supported")
	}

	consulConfig := &consul.Config{
		ConnectionTimeout: 3 * time.Second,
		Token:             config.Token,
		Namespace:         config.Namespace,
	}

	if config.TLS != nil {
		tlsConfig, err := config.TLS.CreateTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configuration: %w", err)
		}
		consulConfig.TLS = tlsConfig
	}

	kvConfig := &KVStoreConfig{
		Endpoints:   config.Endpoints,
		Prefix:      config.Prefix,
		LockTimeout: config.LockTimeout,
	}

	return NewKVStore(ctx, consul.StoreName, consulConfig, kvConfig)
}
