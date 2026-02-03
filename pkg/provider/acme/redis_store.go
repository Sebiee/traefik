package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kvtools/redis"
	"github.com/traefik/traefik/v3/pkg/types"
)

// RedisStoreConfig holds the Redis-specific configuration for ACME storage.
type RedisStoreConfig struct {
	// Endpoints is the list of Redis endpoints.
	Endpoints []string `description:"Redis endpoints." json:"endpoints,omitempty" toml:"endpoints,omitempty" yaml:"endpoints,omitempty"`

	// Username for Redis authentication.
	Username string `description:"Username for Redis authentication." json:"username,omitempty" toml:"username,omitempty" yaml:"username,omitempty" loggable:"false"`

	// Password for Redis authentication.
	Password string `description:"Password for Redis authentication." json:"password,omitempty" toml:"password,omitempty" yaml:"password,omitempty" loggable:"false"`

	// DB is the Redis database to use.
	DB int `description:"Redis database number." json:"db,omitempty" toml:"db,omitempty" yaml:"db,omitempty"`

	// Prefix is the key prefix for ACME data.
	Prefix string `description:"Key prefix for ACME data." json:"prefix,omitempty" toml:"prefix,omitempty" yaml:"prefix,omitempty"`

	// TLS configuration.
	TLS *types.ClientTLS `description:"TLS configuration for Redis connection." json:"tls,omitempty" toml:"tls,omitempty" yaml:"tls,omitempty"`

	// LockTimeout is the timeout for distributed locks.
	LockTimeout time.Duration `description:"Lock timeout for certificate operations." json:"lockTimeout,omitempty" toml:"lockTimeout,omitempty" yaml:"lockTimeout,omitempty"`

	// Sentinel configuration for Redis Sentinel mode.
	Sentinel *RedisSentinelConfig `description:"Redis Sentinel configuration." json:"sentinel,omitempty" toml:"sentinel,omitempty" yaml:"sentinel,omitempty"`
}

// RedisSentinelConfig holds the Redis Sentinel configuration.
type RedisSentinelConfig struct {
	// MasterName is the name of the master.
	MasterName string `description:"Name of the master." json:"masterName,omitempty" toml:"masterName,omitempty" yaml:"masterName,omitempty" export:"true"`

	// Username for Sentinel authentication.
	Username string `description:"Username for Sentinel authentication." json:"username,omitempty" toml:"username,omitempty" yaml:"username,omitempty" loggable:"false"`

	// Password for Sentinel authentication.
	Password string `description:"Password for Sentinel authentication." json:"password,omitempty" toml:"password,omitempty" yaml:"password,omitempty" loggable:"false"`

	// LatencyStrategy routes commands to the closest nodes.
	LatencyStrategy bool `description:"Route commands to closest nodes." json:"latencyStrategy,omitempty" toml:"latencyStrategy,omitempty" yaml:"latencyStrategy,omitempty"`

	// RandomStrategy routes commands randomly to nodes.
	RandomStrategy bool `description:"Route commands randomly to nodes." json:"randomStrategy,omitempty" toml:"randomStrategy,omitempty" yaml:"randomStrategy,omitempty"`

	// ReplicaStrategy routes all commands to replica nodes.
	ReplicaStrategy bool `description:"Route all commands to replica nodes." json:"replicaStrategy,omitempty" toml:"replicaStrategy,omitempty" yaml:"replicaStrategy,omitempty"`

	// UseDisconnectedReplicas allows using disconnected replicas.
	UseDisconnectedReplicas bool `description:"Use replicas disconnected from master." json:"useDisconnectedReplicas,omitempty" toml:"useDisconnectedReplicas,omitempty" yaml:"useDisconnectedReplicas,omitempty"`
}

// SetDefaults sets the default values for RedisStoreConfig.
func (c *RedisStoreConfig) SetDefaults() {
	c.Endpoints = []string{"localhost:6379"}
	c.Prefix = "traefik/acme"
	c.LockTimeout = 30 * time.Second
}

// NewRedisStore creates a new KVStore using Redis as the backend.
func NewRedisStore(ctx context.Context, config *RedisStoreConfig) (*KVStore, error) {
	if config == nil {
		return nil, errors.New("redis configuration is required")
	}

	redisConfig := &redis.Config{
		Username: config.Username,
		Password: config.Password,
		DB:       config.DB,
	}

	if config.TLS != nil {
		tlsConfig, err := config.TLS.CreateTLSConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configuration: %w", err)
		}
		redisConfig.TLS = tlsConfig
	}

	if config.Sentinel != nil {
		count := 0
		if config.Sentinel.LatencyStrategy {
			count++
		}
		if config.Sentinel.ReplicaStrategy {
			count++
		}
		if config.Sentinel.RandomStrategy {
			count++
		}
		if count > 1 {
			return nil, errors.New("latencyStrategy, randomStrategy and replicaStrategy are mutually exclusive")
		}

		clusterClient := config.Sentinel.LatencyStrategy || config.Sentinel.RandomStrategy
		redisConfig.Sentinel = &redis.Sentinel{
			MasterName:              config.Sentinel.MasterName,
			Username:                config.Sentinel.Username,
			Password:                config.Sentinel.Password,
			ClusterClient:           clusterClient,
			RouteByLatency:          config.Sentinel.LatencyStrategy,
			RouteRandomly:           config.Sentinel.RandomStrategy,
			ReplicaOnly:             config.Sentinel.ReplicaStrategy,
			UseDisconnectedReplicas: config.Sentinel.UseDisconnectedReplicas,
		}
	}

	kvConfig := &KVStoreConfig{
		Endpoints:   config.Endpoints,
		Prefix:      config.Prefix,
		LockTimeout: config.LockTimeout,
	}

	return NewKVStore(ctx, redis.StoreName, redisConfig, kvConfig)
}
