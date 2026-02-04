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

Traefik uses **etcd** as the distributed key-value store backend for ACME storage.
etcd is a distributed, reliable key-value store commonly used in Kubernetes environments.

!!! warning "High Availability Considerations"
    etcd can become a single point of failure. For production deployments,
    you should deploy an **etcd cluster with 3+ nodes** for high availability.

    If etcd becomes unreachable during certificate operations, Traefik will
    **skip the certificate request** to prevent duplicate requests. HTTP challenges
    will fall back to local cache.

## Challenge Types

### HTTP-01 Challenge with Distributed Storage

When using HTTP-01 challenge with distributed storage, Traefik automatically:

1. **Shares challenge tokens** across all replicas via etcd
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
      etcd:
        endpoints:
          - "etcd:2379"
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
      etcd:
        endpoints:
          - "etcd:2379"
        prefix: "traefik/acme"
```

### TLS-ALPN-01 Challenge

TLS-ALPN-01 challenge also works with distributed storage, using the same distributed
locking mechanism to prevent race conditions.

## Configuration

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
          - "etcd-1:2379"
          - "etcd-2:2379"
          - "etcd-3:2379"
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
    endpoints = ["etcd-1:2379", "etcd-2:2379", "etcd-3:2379"]
    # username = "traefik"
    # password = "secret"
    prefix = "traefik/acme"
    lockTimeout = "30s"
```

```bash tab="CLI"
--certificatesresolvers.myresolver.acme.email=your-email@example.com
--certificatesresolvers.myresolver.acme.dnschallenge.provider=cloudflare
--certificatesresolvers.myresolver.acme.etcd.endpoints=etcd-1:2379,etcd-2:2379,etcd-3:2379
--certificatesresolvers.myresolver.acme.etcd.prefix=traefik/acme
```

## Docker Swarm Example

### With HTTP-01 Challenge

Here's a complete Docker Swarm deployment with etcd for distributed ACME storage using HTTP-01 challenge:

```yaml
version: "3.8"

services:
  etcd:
    image: quay.io/coreos/etcd:v3.5
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    volumes:
      - etcd-data:/etcd-data
    command:
      - etcd
      - --data-dir=/etcd-data
      - --listen-client-urls=http://0.0.0.0:2379
      - --advertise-client-urls=http://etcd:2379
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
      - "--certificatesresolvers.le.acme.etcd.endpoints=etcd:2379"
      - "--certificatesresolvers.le.acme.etcd.prefix=traefik/acme"
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
  etcd-data:
```

### With DNS-01 Challenge

For DNS-01 challenge using Cloudflare:

```yaml
version: "3.8"

services:
  etcd:
    image: quay.io/coreos/etcd:v3.5
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    volumes:
      - etcd-data:/etcd-data
    command:
      - etcd
      - --data-dir=/etcd-data
      - --listen-client-urls=http://0.0.0.0:2379
      - --advertise-client-urls=http://etcd:2379
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
      - "--certificatesresolvers.le.acme.etcd.endpoints=etcd:2379"
      - "--certificatesresolvers.le.acme.etcd.prefix=traefik/acme"
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
  etcd-data:
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `endpoints` | List of etcd endpoints | `127.0.0.1:2379` |
| `prefix` | Key prefix for ACME data | `traefik/acme` |
| `lockTimeout` | Timeout for distributed locks | `30s` |
| `username` | Username for authentication | - |
| `password` | Password for authentication | - |
| `tls.ca` | Path to CA certificate for TLS | - |
| `tls.cert` | Path to client certificate for TLS | - |
| `tls.key` | Path to client key for TLS | - |
| `tls.insecureSkipVerify` | Skip TLS verification | `false` |

## Multiple Resolvers

If you configure multiple resolvers (e.g., for different ACME providers or accounts),
Traefik handles them separately within the store.

### Using the Same etcd Instance (Recommended)

When multiple resolvers point to the same etcd instance with the **same prefix**,
Traefik reuses the connection and efficiently manages resources. Data is automatically
namespaced by the resolver name (e.g., `<prefix>/data/<resolverName>`).

```yaml
certificatesResolvers:
  # First resolver (Let's Encrypt Staging)
  staging:
    acme:
      email: ...
      etcd:
        endpoints: ["etcd:2379"]
        prefix: "traefik/acme"  # Same prefix

  # Second resolver (Let's Encrypt Production)
  production:
    acme:
      email: ...
      etcd:
        endpoints: ["etcd:2379"]
        prefix: "traefik/acme"  # Same prefix
```

### Using Different etcd Clusters

If you need to use different etcd clusters, you **must use different prefixes**.
Traefik uses the prefix to identify shared connections, so resolvers with the same prefix
will share the same etcd connection (even if endpoints differ in configuration).

```yaml
certificatesResolvers:
  # First resolver (Cluster A)
  resolverA:
    acme:
      etcd:
        endpoints: ["etcd-cluster-a:2379"]
        prefix: "traefik/acme-a"  # Different prefix

  # Second resolver (Cluster B)
  resolverB:
    acme:
      etcd:
        endpoints: ["etcd-cluster-b:2379"]
        prefix: "traefik/acme-b"  # Different prefix
```

## How It Works

1. **Distributed Locking**: Before obtaining a certificate, Traefik acquires a distributed lock
   for the domain. This ensures only one replica handles certificate operations for each domain.

2. **Shared Storage**: Certificates are stored in etcd and automatically synced to all replicas.

3. **Watch for Updates**: Replicas watch etcd for changes and automatically load new
   certificates when another replica obtains them.

4. **Compression**: Certificate data is compressed before storage to reduce storage usage.

## Resilience and Fallback Behavior

Traefik handles etcd unavailability gracefully:

### etcd Unreachable

When etcd is down or unreachable:

- **Certificate Requests**: Traefik **skips** new certificate requests if it cannot acquire
  a distributed lock. This prevents duplicate requests across replicas.

- **HTTP Challenge Tokens**: The distributed challenge provider uses its **local cache**
  to serve challenge responses. Tokens are always cached locally in addition to etcd.

- **Existing Certificates**: Certificates loaded at startup remain in memory and continue to work.

### Recommendations for Production

To minimize the impact of etcd failures:

1. **Deploy a 3+ node etcd cluster** for quorum-based high availability
2. **Monitor etcd health** and set up alerts
3. **Use TLS** for secure communication between Traefik and etcd
4. **Regular backups** of etcd data for disaster recovery

### What Happens During Degraded Mode

| Scenario | Behavior |
|----------|----------|
| etcd down during cert request | Skips request (prevents duplicates) |
| etcd down during challenge | Uses local cache to respond |
| etcd recovers | Automatically reconnects and syncs |
| Lock already held by another replica | Waits up to 60s, then checks if cert was obtained |

## Migration from Local Storage

To migrate from local file storage to distributed storage:

1. Stop all Traefik replicas except one
2. Configure etcd on the remaining replica
3. Start it - certificates will be read from the local file and stored in etcd
4. Stop the replica and remove the `storage` option
5. Start all replicas with the etcd configuration

!!! note "File Storage Override"
    The `storage` (file) option is ignored when etcd is configured.
