---
title: "Distributed ACME Storage"
description: "Configure distributed ACME certificate storage for running multiple Traefik replicas."
---

# Distributed ACME Storage

When running multiple Traefik replicas (e.g., in Docker Swarm or Kubernetes),
you need distributed storage for ACME certificates to avoid:

- **Race conditions**: Multiple replicas trying to obtain certificates for the same domain
- **Let's Encrypt rate limiting**: Duplicate certificate requests consuming rate limits
- **Challenge failures**: Wrong replica receiving ACME challenges

Traefik supports three distributed KV store backends for ACME storage:

- **Redis**: Simple, fast, widely used
- **Consul**: Full-featured service mesh with built-in KV store
- **etcd**: Distributed key-value store, popular in Kubernetes environments

!!! warning "High Availability Considerations"
    The KV store itself can become a single point of failure. For production deployments,
    you should use:

    - **Redis Sentinel** or **Redis Cluster** for Redis HA
    - **Consul cluster** (3+ nodes) for Consul HA
    - **etcd cluster** (3+ nodes) for etcd HA

    If the KV store becomes unreachable, Traefik will **automatically fall back to local-only mode**
    and continue operating. However, in this degraded state, multiple replicas may issue
    duplicate certificate requests.

## Challenge Types

### HTTP-01 Challenge with Distributed Storage

When using HTTP-01 challenge with distributed storage, Traefik automatically:

1. **Shares challenge tokens** across all replicas via the KV store
2. **Uses distributed locking** to prevent multiple replicas from requesting the same certificate
3. **Syncs certificates** to all replicas after issuance

This means any replica can respond to ACME HTTP-01 challenges, and you can safely run
multiple Traefik replicas with HTTP-01 challenge type.

```yaml tab="File (YAML)"
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      httpChallenge:
        entryPoint: web
      redis:
        endpoints:
          - "redis:6379"
        prefix: "traefik/acme"
```

### DNS-01 Challenge

DNS-01 challenge is also fully supported with distributed storage. It doesn't require
any special handling since the challenge is verified via DNS records, not HTTP requests.

```yaml tab="File (YAML)"
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      dnsChallenge:
        provider: cloudflare
      redis:
        endpoints:
          - "redis:6379"
        prefix: "traefik/acme"
```

### TLS-ALPN-01 Challenge

TLS-ALPN-01 challenge also works with distributed storage, using the same distributed
locking mechanism to prevent race conditions.

## Configuration

### Redis

Redis is the simplest option for distributed ACME storage.

```yaml tab="File (YAML)"
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      dnsChallenge:
        provider: cloudflare
      redis:
        endpoints:
          - "redis:6379"
        # Optional authentication
        # username: traefik
        # password: secret
        # db: 0
        prefix: "traefik/acme"
        lockTimeout: 30s
```

```toml tab="File (TOML)"
[certificatesResolvers.myresolver.acme]
  email = "your-email@example.com"

  [certificatesResolvers.myresolver.acme.dnsChallenge]
    provider = "cloudflare"

  [certificatesResolvers.myresolver.acme.redis]
    endpoints = ["redis:6379"]
    # username = "traefik"
    # password = "secret"
    # db = 0
    prefix = "traefik/acme"
    lockTimeout = "30s"
```

```bash tab="CLI"
--certificatesresolvers.myresolver.acme.email=your-email@example.com
--certificatesresolvers.myresolver.acme.dnschallenge.provider=cloudflare
--certificatesresolvers.myresolver.acme.redis.endpoints=redis:6379
--certificatesresolvers.myresolver.acme.redis.prefix=traefik/acme
```

#### Redis Sentinel

For high availability Redis setups using Sentinel:

```yaml tab="File (YAML)"
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      dnsChallenge:
        provider: cloudflare
      redis:
        endpoints:
          - "sentinel1:26379"
          - "sentinel2:26379"
          - "sentinel3:26379"
        sentinel:
          masterName: mymaster
          # Optional Sentinel authentication
          # username: sentinel-user
          # password: sentinel-pass
```

### Consul

```yaml tab="File (YAML)"
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      dnsChallenge:
        provider: cloudflare
      consul:
        endpoints:
          - "consul:8500"
        # Optional ACL token
        # token: your-acl-token
        # namespace: default  # Consul Enterprise only
        prefix: "traefik/acme"
        lockTimeout: 30s
```

```toml tab="File (TOML)"
[certificatesResolvers.myresolver.acme]
  email = "your-email@example.com"

  [certificatesResolvers.myresolver.acme.dnsChallenge]
    provider = "cloudflare"

  [certificatesResolvers.myresolver.acme.consul]
    endpoints = ["consul:8500"]
    # token = "your-acl-token"
    prefix = "traefik/acme"
    lockTimeout = "30s"
```

### etcd

```yaml tab="File (YAML)"
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      dnsChallenge:
        provider: cloudflare
      etcd:
        endpoints:
          - "etcd:2379"
        # Optional authentication
        # username: traefik
        # password: secret
        prefix: "traefik/acme"
        lockTimeout: 30s
```

```toml tab="File (TOML)"
[certificatesResolvers.myresolver.acme]
  email = "your-email@example.com"

  [certificatesResolvers.myresolver.acme.dnsChallenge]
    provider = "cloudflare"

  [certificatesResolvers.myresolver.acme.etcd]
    endpoints = ["etcd:2379"]
    # username = "traefik"
    # password = "secret"
    prefix = "traefik/acme"
    lockTimeout = "30s"
```

## Docker Swarm Example

### With HTTP-01 Challenge (Recommended for most users)

Here's a complete Docker Swarm deployment with Redis for distributed ACME storage using HTTP-01 challenge:

```yaml
version: "3.8"

services:
  redis:
    image: redis:7-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    networks:
      - traefik-net

  traefik:
    image: traefik:v3
    deploy:
      replicas: 3  # Multiple replicas!
      placement:
        constraints:
          - node.role == manager
    ports:
      - "80:80"
      - "443:443"
    command:
      - "--providers.swarm=true"
      - "--providers.swarm.exposedByDefault=false"
      - "--entryPoints.web.address=:80"
      - "--entryPoints.websecure.address=:443"
      - "--certificatesresolvers.le.acme.email=your@email.com"
      - "--certificatesresolvers.le.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.le.acme.redis.endpoints=redis:6379"
      - "--certificatesresolvers.le.acme.redis.prefix=traefik/acme"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - traefik-net

  whoami:
    image: traefik/whoami
    deploy:
      replicas: 2
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
        - "traefik.http.routers.whoami.tls.certresolver=le"
        - "traefik.http.services.whoami.loadbalancer.server.port=80"
    networks:
      - traefik-net

networks:
  traefik-net:
    driver: overlay

volumes:
  redis-data:
```

### With DNS-01 Challenge

For DNS-01 challenge using Cloudflare:

```yaml
version: "3.8"

services:
  redis:
    image: redis:7-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    networks:
      - traefik-net

  traefik:
    image: traefik:v3
    deploy:
      replicas: 3  # Multiple replicas!
      placement:
        constraints:
          - node.role == manager
    ports:
      - "80:80"
      - "443:443"
    environment:
      - CF_API_EMAIL=your@email.com
      - CF_API_KEY=your-cloudflare-api-key
    command:
      - "--providers.swarm=true"
      - "--providers.swarm.exposedByDefault=false"
      - "--entryPoints.web.address=:80"
      - "--entryPoints.websecure.address=:443"
      - "--certificatesresolvers.le.acme.email=your@email.com"
      - "--certificatesresolvers.le.acme.dnschallenge.provider=cloudflare"
      - "--certificatesresolvers.le.acme.redis.endpoints=redis:6379"
      - "--certificatesresolvers.le.acme.redis.prefix=traefik/acme"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - traefik-net

  whoami:
    image: traefik/whoami
    deploy:
      replicas: 2
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
        - "traefik.http.routers.whoami.tls.certresolver=le"
        - "traefik.http.services.whoami.loadbalancer.server.port=80"
    networks:
      - traefik-net

networks:
  traefik-net:
    driver: overlay

volumes:
  redis-data:
```

## Configuration Options

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `endpoints` | List of KV store endpoints | Backend-specific |
| `prefix` | Key prefix for ACME data | `traefik/acme` |
| `lockTimeout` | Timeout for distributed locks | `30s` |
| `tls.ca` | CA certificate for TLS | - |
| `tls.cert` | Client certificate for TLS | - |
| `tls.key` | Client key for TLS | - |
| `tls.insecureSkipVerify` | Skip TLS verification | `false` |

### Redis-Specific Options

| Option | Description | Default |
|--------|-------------|---------|
| `username` | Username for authentication | - |
| `password` | Password for authentication | - |
| `db` | Redis database number | `0` |
| `sentinel.masterName` | Sentinel master name | - |
| `sentinel.username` | Sentinel username | - |
| `sentinel.password` | Sentinel password | - |

### Consul-Specific Options

| Option | Description | Default |
|--------|-------------|---------|
| `token` | ACL token | - |
| `namespace` | Consul namespace (Enterprise) | - |

### etcd-Specific Options

| Option | Description | Default |
|--------|-------------|---------|
| `username` | Username for authentication | - |
| `password` | Password for authentication | - |

## How It Works

1. **Distributed Locking**: Before obtaining a certificate, Traefik acquires a distributed lock
   for the domain. This ensures only one replica handles certificate operations for each domain.

2. **Shared Storage**: Certificates are stored in the KV store and automatically synced to all replicas.

3. **Watch for Updates**: Replicas watch the KV store for changes and automatically load new
   certificates when another replica obtains them.

4. **Compression**: Certificate data is compressed before storage to reduce KV store usage.

## Resilience and Fallback Behavior

Traefik is designed to be resilient when the KV store becomes unavailable:

### KV Store Unreachable

When the KV store is down or unreachable:

- **Certificate Resolution**: Traefik will fall back to **local-only mode** and continue
  processing certificate requests. A warning is logged, but operations proceed.

- **HTTP Challenge Tokens**: The distributed challenge provider will use its **local cache**
  to serve challenge responses. Tokens are always cached locally in addition to the KV store.

- **Existing Certificates**: Certificates loaded at startup remain in memory and continue to work.

### Recommendations for Production

To minimize the impact of KV store failures:

1. **Use Redis Sentinel or Cluster** for automatic failover
2. **Deploy 3+ node Consul/etcd clusters** for quorum-based HA
3. **Monitor KV store health** and set up alerts
4. **Consider read replicas** for Redis to distribute load

### What Happens During Degraded Mode

| Scenario | Behavior |
|----------|----------|
| KV store down during cert request | Proceeds with local-only mode (may cause duplicates) |
| KV store down during challenge | Uses local cache to respond |
| KV store recovers | Automatically reconnects and syncs |
| Lock already held | Skips cert request (correct behavior) |

## Migration from Local Storage

To migrate from local file storage to distributed storage:

1. Stop all Traefik replicas except one
2. Configure the distributed store on the remaining replica
3. Start it - certificates will be read from the local file and stored in the KV store
4. Stop the replica and remove the `storage` option
5. Start all replicas with the distributed store configuration

!!! warning "Mutual Exclusivity"
    You can only configure one distributed store at a time. The `storage` (file) option
    is ignored when a distributed store is configured.
