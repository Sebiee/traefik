package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/kvtools/etcdv3"
	"github.com/kvtools/valkeyrie"
	"github.com/kvtools/valkeyrie/store"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/traefik/traefik/v3/integration/try"
	"github.com/traefik/traefik/v3/pkg/testhelpers"
)

// AcmeEtcdMultiReplicaSuite tests ACME certificate storage with etcd backend.
type AcmeEtcdMultiReplicaSuite struct {
	BaseSuite

	pebbleIP      string
	etcdAddr      string
	kvClient      store.Store
	fakeDNSServer *dns.Server
}

func TestAcmeEtcdMultiReplicaSuite(t *testing.T) {
	suite.Run(t, new(AcmeEtcdMultiReplicaSuite))
}

func (s *AcmeEtcdMultiReplicaSuite) getAcmeURL() string {
	return fmt.Sprintf("https://%s/dir", net.JoinHostPort(s.pebbleIP, "14000"))
}

func (s *AcmeEtcdMultiReplicaSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.createComposeProject("acme_etcd_renewal")
	s.composeUp()

	// Setup etcd client
	var err error
	s.etcdAddr = net.JoinHostPort(s.getComposeServiceIP("etcd"), "2379")
	s.kvClient, err = valkeyrie.NewStore(
		s.T().Context(),
		etcdv3.StoreName,
		[]string{s.etcdAddr},
		&etcdv3.Config{
			ConnectionTimeout: 10 * time.Second,
		},
	)
	require.NoError(s.T(), err)

	// Wait for etcd
	err = try.Do(30*time.Second, try.KVExists(s.kvClient, "test"))
	require.NoError(s.T(), err)

	// Setup pebble
	s.fakeDNSServer = startFakeDNSServer(s.hostIP)
	s.pebbleIP = s.getComposeServiceIP("pebble")

	pebbleTransport, err := setupPebbleRootCA()
	require.NoError(s.T(), err)

	// Wait for pebble
	req := testhelpers.MustNewRequest(http.MethodGet, s.getAcmeURL(), nil)
	client := &http.Client{Transport: pebbleTransport}

	err = try.Do(5*time.Second, func() error {
		resp, errGet := client.Do(req)
		if errGet != nil {
			return errGet
		}
		return try.StatusCodeIs(http.StatusOK)(resp)
	})
	require.NoError(s.T(), err)
}

func (s *AcmeEtcdMultiReplicaSuite) TearDownSuite() {
	s.BaseSuite.TearDownSuite()

	if s.fakeDNSServer != nil {
		err := s.fakeDNSServer.Shutdown()
		if err != nil {
			log.Info().Msg(err.Error())
		}
	}

	s.composeDown()
}

func (s *AcmeEtcdMultiReplicaSuite) TearDownTest() {
	// Defensive cleanup after test - errors are logged but don't fail the test
	ctx := context.Background()
	if err := s.kvClient.DeleteTree(ctx, "/"); err != nil {
		s.T().Logf("Warning: TearDownTest cleanup failed: %v", err)
	}
}

func (s *AcmeEtcdMultiReplicaSuite) BeforeTest(_, _ string) {
	ctx := context.Background()

	// VERIFY etcd is completely empty - list all keys and assert none exist
	pairs, err := s.kvClient.List(ctx, "/", nil)
	require.Error(s.T(), err, "etcd should be empty before test")
	require.Empty(s.T(), pairs, "etcd is NOT empty before test - cleanup failed. Found keys: %+v", pairs)
}

func (s *AcmeEtcdMultiReplicaSuite) printOrderlyLogs(traefikLogs []*bytes.Buffer) {
	type logEntry struct {
		replica   int
		timestamp time.Time
		line      string
	}

	var allLogs []logEntry

	for i, logBuf := range traefikLogs {
		logContent := logBuf.String()
		lines := strings.Split(logContent, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			// Filter for relevant log lines
			if !strings.Contains(line, "renew") && !strings.Contains(line, "Renew") &&
				!strings.Contains(line, "lock") && !strings.Contains(line, "Lock") &&
				!strings.Contains(line, "refresh") && !strings.Contains(line, "Refresh") &&
				!strings.Contains(line, "Acquired") && !strings.Contains(line, "Released") &&
				!strings.Contains(line, "ACME") && !strings.Contains(line, "acme") &&
				!strings.Contains(line, "challenge") && !strings.Contains(line, "Challenge") &&
				!strings.Contains(line, "token") && !strings.Contains(line, "Token") &&
				!strings.Contains(line, "certificate") && !strings.Contains(line, "Certificate") {
				continue
			}

			// Parse timestamp from log line
			// Console format: "2006-01-02T15:04:05.999999999+07:00 DBG ..." (timestamp at start)
			// JSON format: {"time":"2006-01-02T15:04:05.999999999Z07:00",...}
			var ts time.Time
			formats := []string{
				time.RFC3339Nano,
				time.RFC3339,
			}

			// Try console format first (timestamp at beginning of line)
			// With nanoseconds, timestamp can be up to ~35 chars, search up to 45 for safety
			if len(line) >= 25 {
				for endIdx := 19; endIdx < len(line) && endIdx < 45; endIdx++ {
					if line[endIdx] == ' ' {
						timeStr := line[:endIdx]
						for _, format := range formats {
							if parsed, parseErr := time.Parse(format, timeStr); parseErr == nil {
								ts = parsed
								break
							}
						}
						if !ts.IsZero() {
							break
						}
					}
				}
			}

			// Try JSON format if console format didn't work
			if ts.IsZero() {
				if idx := strings.Index(line, `"time":"`); idx != -1 {
					start := idx + 8
					if end := strings.Index(line[start:], `"`); end != -1 {
						timeStr := line[start : start+end]
						for _, format := range formats {
							if parsed, parseErr := time.Parse(format, timeStr); parseErr == nil {
								ts = parsed
								break
							}
						}
					}
				}
			}

			allLogs = append(allLogs, logEntry{
				replica:   i + 1,
				timestamp: ts,
				line:      line,
			})
		}
	}

	// Sort by timestamp
	slices.SortFunc(allLogs, func(a, b logEntry) int {
		if a.timestamp.Before(b.timestamp) {
			return -1
		}
		if a.timestamp.After(b.timestamp) {
			return 1
		}
		return a.replica - b.replica // tie-breaker: lower replica first
	})

	// Print interleaved logs with replica identifier and precise timestamp (capped to avoid CI log bloat)
	const maxLogEntries = 1000
	s.T().Log("=== Interleaved Traefik Replica Logs (sorted by timestamp) ===")
	startIdx := 0
	if len(allLogs) > maxLogEntries {
		startIdx = len(allLogs) - maxLogEntries
		s.T().Logf("(showing last %d of %d entries)", maxLogEntries, len(allLogs))
	}
	for _, entry := range allLogs[startIdx:] {
		tsStr := entry.timestamp.Format("15:04:05.000000")
		s.T().Logf("[R%d %s] %s", entry.replica, tsStr, entry.line)
	}
	s.T().Logf("=== End of logs (%d total entries, showed last %d) ===", len(allLogs), len(allLogs)-startIdx)
}

// getPebbleOrderCount reads the Pebble container logs and counts the number of orders.
// Pebble logs "There are now N orders in the db" each time an order is added.
// Returns the final order count (the maximum N seen in the logs).
// ATTENTION! CONSIDER THE FACT THAT THERE'S ONE PEEBLE INSTANCE FOR ALL TESTS IN THIS SUITE - IF YOU RUN MULTIPLE TESTS, THE ORDER COUNT WILL BE CUMULATIVE ACROSS TESTS. THIS FUNCTION SHOULD ONLY BE USED IN TESTS THAT KNOW EXACTLY HOW MANY ORDERS TO EXPECT IN TOTAL.
func (s *AcmeEtcdMultiReplicaSuite) getPebbleOrderCount() (int, error) {
	pebbleContainer, ok := s.containers["pebble"]
	if !ok {
		return 0, errors.New("pebble container not found")
	}

	ctx := s.T().Context()
	readCloser, err := pebbleContainer.Logs(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get pebble logs: %w", err)
	}
	defer readCloser.Close()

	logContent, err := io.ReadAll(readCloser)
	if err != nil {
		return 0, fmt.Errorf("failed to read pebble logs: %w", err)
	}

	// Pattern: "There are now N orders in the db"
	re := regexp.MustCompile(`There are now (\d+) orders in the db`)
	matches := re.FindAllStringSubmatch(string(logContent), -1)

	maxOrders := 0
	for _, match := range matches {
		if len(match) >= 2 {
			var count int
			_, err := fmt.Sscanf(match[1], "%d", &count)
			if err == nil && count > maxOrders {
				maxOrders = count
			}
		}
	}

	return maxOrders, nil
}

// TestThunderingHerdMultiReplica does the same thing as the TestThunderingHerd test,
// but with multiple Traefik replicas behind an nginx load balancer to simulate
// a realistic distributed setup.
// Architecture:
// - nginx load balancer on port 5002 (the port Pebble expects for HTTP-01)
// - 3 Traefik replicas on ports 5102, 5202, 5302
// - All replicas share etcd for distributed certificate storage
// - Pebble validates challenges via the load balancer
func (s *AcmeEtcdMultiReplicaSuite) TestThunderingHerdMultiReplica() {
	const numDomains = 15
	const numReplicas = 2

	// Timeouts must account for serial certificate issuance (2-3s per domain)
	// Plus extra buffer for network latency, retries, and CI slowness
	certWaitTimeout := time.Duration(numDomains*3+60) * time.Second
	consistencyTimeout := time.Duration(numDomains*3+60) * time.Second
	renewalTimeout := time.Duration(numDomains*3+120) * time.Second

	ctx := context.Background()

	// Generate domains
	endpoints := make(map[string]x509.Certificate, numDomains)
	for i := range numDomains {
		endpoints[fmt.Sprintf("domain%d.acme.wtf", i)] = x509.Certificate{}
	}

	// Start backend
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	lbHTTPSPort := 5001 // nginx load balancer HTTPS port
	lbHTTPPort := 5002  // nginx load balancer HTTP port
	portHTTPStart := 5102
	portHTTPSStart := 5101
	portAPIStart := 5103
	allHTTPPorts := []int{}
	for i := range numReplicas {
		allHTTPPorts = append(allHTTPPorts, portHTTPStart+i*100)
	}
	allHTTPSPorts := []int{}
	for i := range numReplicas {
		allHTTPSPorts = append(allHTTPSPorts, portHTTPSStart+i*100)
	}

	// Start nginx LB FIRST
	// Must be ready BEFORE Traefik replicas start, otherwise Pebble can't validate challenges
	lbConfigFile := s.adaptFile("fixtures/acme/acme_etcd_multireplica_nginx.conf.tpl", struct {
		HTTPPorts   []int
		HTTPSPorts  []int
		LBHTTPPort  int
		LBHTTPSPort int
	}{
		LBHTTPPort:  lbHTTPPort,
		LBHTTPSPort: lbHTTPSPort,
		HTTPPorts:   allHTTPPorts,
		HTTPSPorts:  allHTTPSPorts,
	})

	nginxReq := testcontainers.ContainerRequest{
		Image:        "nginx:alpine",
		ExposedPorts: []string{fmt.Sprintf("%d/tcp", lbHTTPPort), fmt.Sprintf("%d/tcp", lbHTTPSPort)},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = []string{"host.docker.internal:host-gateway"}
			hc.PortBindings = map[nat.Port][]nat.PortBinding{
				nat.Port(fmt.Sprintf("%d/tcp", lbHTTPPort)):  {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(lbHTTPPort)}},
				nat.Port(fmt.Sprintf("%d/tcp", lbHTTPSPort)): {{HostIP: "0.0.0.0", HostPort: strconv.Itoa(lbHTTPSPort)}},
			}
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      lbConfigFile,
				ContainerFilePath: "/etc/nginx/nginx.conf",
				FileMode:          0o644,
			},
		},
		WaitingFor: wait.ForLog("Configuration complete").WithStartupTimeout(10 * time.Second),
	}

	nginxC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: nginxReq,
		Started:          true,
	})
	require.NoError(s.T(), err)
	defer func() { _ = nginxC.Terminate(ctx) }()

	// Start 3 Traefik replicas AFTER LB is ready
	var traefikLogs []*bytes.Buffer
	for i := range numReplicas {
		template := thunderingHerdTemplateModel{
			PortHTTP:    fmt.Sprintf(":%d", portHTTPStart+i*100),  // 5102, 5202, 5302
			PortHTTPS:   fmt.Sprintf(":%d", portHTTPSStart+i*100), // 5101, 5201, 5301
			PortAPI:     fmt.Sprintf(":%d", portAPIStart+i*100),   // 5103, 5203, 5303
			EtcdAddress: s.etcdAddr,
			CAServer:    s.getAcmeURL(),
			Domains:     slices.Collect(maps.Keys(endpoints)),
		}

		file := s.adaptFile("fixtures/acme/acme_etcd_thundering_herd.toml", template)
		cmd, logBuf := s.cmdTraefik(withConfigFile(file))
		traefikLogs = append(traefikLogs, logBuf)
		defer s.killCmd(cmd)
	}

	s.T().Cleanup(func() {
		if s.T().Failed() || *showLog {
			s.displayLogCompose()
			s.printOrderlyLogs(traefikLogs)
		}
	})

	// Wait for replicas to start
	for i := range numReplicas {
		apiURL := fmt.Sprintf("http://127.0.0.1:%d/ping", portAPIStart+i*100)
		err = try.Do(15*time.Second, func() error {
			resp, errReq := http.Get(apiURL)
			if errReq != nil {
				return errReq
			}
			responseText, errRead := io.ReadAll(resp.Body)
			resp.Body.Close()
			if errRead != nil {
				return errRead
			}
			if resp.StatusCode != http.StatusOK || string(responseText) != "OK" {
				return fmt.Errorf("replica %d ping returned %d", i+1, resp.StatusCode)
			}
			return nil
		})
		require.NoError(s.T(), err, "Replica %d did not start", i+1)
	}

	// Use the LB port (5001) for HTTPS requests - nginx proxies to all replicas
	// Wait for ACME certificates to be issued - the cert must contain the requested domain
	s.T().Log("Verifying that all domains are served with a valid certificate via nginx...")
	startTime := time.Now()
	for domain := range endpoints {
		err := try.Do(certWaitTimeout, func() error {
			// Create a new client for each domain with proper TLS SNI
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain, // Set SNI for proper cert matching
					},
					DisableKeepAlives: true,
				},
			}
			req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", lbHTTPSPort), nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s", domain)
			}
			// Verify the certificate is for the requested domain (not just any cert)
			cert := *resp.TLS.PeerCertificates[0]
			if cert.Subject.CommonName != domain && !slices.Contains(cert.DNSNames, domain) {
				return fmt.Errorf("cert for %s not yet available (got CN=%s, DNSNames=%v)",
					domain, cert.Subject.CommonName, cert.DNSNames)
			}
			endpoints[domain] = cert
			return nil
		})
		require.NoError(s.T(), err, "No cert served for %s", domain)
	}
	elapsed := time.Since(startTime)
	s.T().Logf("All %d domains are served with a valid certificate via nginx (%v)", numDomains, elapsed)

	s.T().Log("Verifying that all replicas serve the same certificate for each domain...")

	// Poll until ALL domains have consistent certificates across ALL replicas.
	// This is a single atomic check - either everything is consistent or we keep waiting.
	err = try.Do(consistencyTimeout, func() error {
		for domain, cert := range endpoints {
			expectedSerial := cert.SerialNumber.String()
			verifyClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}
			for i := range numReplicas {
				req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", portHTTPSStart+i*100), nil)
				req.Host = domain
				resp, errReq := verifyClient.Do(req)
				if errReq != nil {
					return fmt.Errorf("replica %d unreachable for %s: %w", i+1, domain, errReq)
				}
				resp.Body.Close()

				if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
					return fmt.Errorf("no TLS cert from replica %d for %s", i+1, domain)
				}

				serial := resp.TLS.PeerCertificates[0].SerialNumber.String()
				if serial != expectedSerial {
					return fmt.Errorf("CONSISTENCY VIOLATION: %s has serial %s on nginx, but serial %s on replica %d",
						domain, expectedSerial, serial, i+1)
				}
			}
		}
		return nil
	})
	require.NoError(s.T(), err, "Certificate consistency check FAILED - distributed storage is broken")
	s.T().Logf("VERIFIED: All %d domains have identical certificates across all %d replicas", numDomains, numReplicas)

	s.T().Log("Checking Pebble order count to ensure that there was only one ACME order per domain...")
	orderCount, err := s.getPebbleOrderCount()
	require.NoError(s.T(), err, "Failed to get Pebble order count")
	require.Equal(s.T(), numDomains, orderCount,
		"Distributed locking failed: expected %d orders, but Pebble received %d orders. "+
			"This indicates multiple replicas created duplicate certificate requests.",
		numDomains, orderCount)
	s.T().Logf("VERIFIED: Pebble received %d orders, one for each of the %d domains", orderCount, numDomains)

	s.T().Log("Waiting for certificates to be renewed...")
	startTime = time.Now()
	for domain := range endpoints {
		err := try.Do(renewalTimeout, func() error {
			// Create a new client for each domain with proper TLS SNI
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain, // Set SNI for proper cert matching
					},
					DisableKeepAlives: true,
				},
			}
			req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", lbHTTPSPort), nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s", domain)
			}
			// Verify the certificate is for the requested domain (not just any cert)
			newCert := *resp.TLS.PeerCertificates[0]
			if newCert.Subject.CommonName != domain && !slices.Contains(newCert.DNSNames, domain) {
				return fmt.Errorf("new cert for %s has wrong domain (got CN=%s, DNSNames=%v)",
					domain, newCert.Subject.CommonName, newCert.DNSNames)
			}

			newSerial := newCert.SerialNumber.String()
			newNotAfter := newCert.NotAfter
			knownSerial := endpoints[domain].SerialNumber.String()
			knownNotAfter := endpoints[domain].NotAfter
			// Check if certificate has been renewed (different serial and later expiry)
			if newSerial == knownSerial {
				return fmt.Errorf("Certificate for %s was not renewed yet (still serial %s)",
					domain, newSerial)
			}
			if newNotAfter.Before(knownNotAfter) || newNotAfter.Equal(knownNotAfter) {
				return fmt.Errorf("Certificate for %s was not renewed yet (still expires %s)",
					domain, knownNotAfter)
			}
			endpoints[domain] = newCert
			return nil
		})
		require.NoError(s.T(), err, "No renewed cert served for %s", domain)
	}
	elapsed = time.Since(startTime)
	s.T().Logf("All %d domains are served with renewed certificates via nginx (%v)", numDomains, elapsed)

	// Poll until ALL domains have consistent certificates across ALL replicas.
	// This is a single atomic check - either everything is consistent or we keep waiting.
	err = try.Do(consistencyTimeout, func() error {
		for domain, cert := range endpoints {
			expectedSerial := cert.SerialNumber.String()
			verifyClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}
			for i := range numReplicas {
				req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", portHTTPSStart+i*100), nil)
				req.Host = domain
				resp, errReq := verifyClient.Do(req)
				if errReq != nil {
					return fmt.Errorf("replica %d unreachable for %s: %w", i+1, domain, errReq)
				}
				resp.Body.Close()

				if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
					return fmt.Errorf("no TLS cert from replica %d for %s", i+1, domain)
				}

				serial := resp.TLS.PeerCertificates[0].SerialNumber.String()
				if serial != expectedSerial {
					return fmt.Errorf("CONSISTENCY VIOLATION: %s has serial %s on replica 1, but %s on replica %d",
						domain, expectedSerial, serial, i+1)
				}
			}
		}
		return nil
	})
	require.NoError(s.T(), err, "Certificate consistency check FAILED after renewal - distributed storage is broken")
	s.T().Logf("VERIFIED: All %d domains have identical RENEWED certificates across all %d replicas", numDomains, numReplicas)

	s.T().Log("Checking Pebble order count to ensure that there was only one ACME order per domain after renewal...")
	orderCount, err = s.getPebbleOrderCount()
	require.NoError(s.T(), err, "Failed to get Pebble order count")
	require.Equal(s.T(), numDomains*2, orderCount,
		"Distributed locking failed: expected %d orders, but Pebble received %d orders. "+
			"This indicates multiple replicas created duplicate certificate requests.",
		numDomains*2, orderCount)
	s.T().Logf("VERIFIED: Pebble order count is now at %d, having received two orders (gen+renew) for each of the %d domains", orderCount, numDomains)
}
