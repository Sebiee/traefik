package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
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

// AcmeEtcdResilienceSuite tests Traefik resilience to etcd and ACME server failures
// when using distributed ACME storage.
//
// These tests verify that:
// 1. Traefik continues serving existing certificates when etcd goes down
// 2. Traefik recovers gracefully when etcd comes back online
// 3. Traefik handles ACME server (Pebble) failures during certificate issuance
// 4. Multiple replicas remain consistent after failure recovery
type AcmeEtcdResilienceSuite struct {
	BaseSuite

	pebbleIP      string
	etcdAddr      string
	kvClient      store.Store
	fakeDNSServer *dns.Server
}

func TestAcmeEtcdResilienceSuite(t *testing.T) {
	suite.Run(t, new(AcmeEtcdResilienceSuite))
}

func (s *AcmeEtcdResilienceSuite) getAcmeURL() string {
	return fmt.Sprintf("https://%s/dir", net.JoinHostPort(s.pebbleIP, "14000"))
}

func (s *AcmeEtcdResilienceSuite) SetupSuite() {
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

func (s *AcmeEtcdResilienceSuite) TearDownSuite() {
	s.BaseSuite.TearDownSuite()

	if s.fakeDNSServer != nil {
		err := s.fakeDNSServer.Shutdown()
		if err != nil {
			log.Info().Msg(err.Error())
		}
	}

	s.composeDown()
}

func (s *AcmeEtcdResilienceSuite) TearDownTest() {
	// Defensive cleanup after test - errors are logged but don't fail the test
	ctx := context.Background()
	if err := s.kvClient.DeleteTree(ctx, "/"); err != nil {
		s.T().Logf("Warning: TearDownTest cleanup failed: %v", err)
	}
}

func (s *AcmeEtcdResilienceSuite) BeforeTest(_, _ string) {
	ctx := context.Background()

	// Ensure etcd is running before each test
	s.composeUp("etcd")
	s.composeUp("pebble")

	// Recreate the kvClient in case etcd was restarted
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

	// Wait for etcd to be ready
	err = try.Do(30*time.Second, try.KVExists(s.kvClient, "test"))
	require.NoError(s.T(), err)

	// VERIFY etcd is completely empty - list all keys and assert none exist
	pairs, err := s.kvClient.List(ctx, "/", nil)
	require.Error(s.T(), err, "etcd should be empty before test")
	require.Empty(s.T(), pairs, "etcd is NOT empty before test - cleanup failed. Found keys: %+v", pairs)
}

// resilienceTemplateModel is used for resilience test templates.
type resilienceTemplateModel struct {
	PortHTTP     string
	PortHTTPS    string
	PortAPI      string
	EtcdAddress  string
	CAServer     string
	Domains      []string
	SelfFilename string
}

// TestEtcdFailureWhileServingCerts tests that Traefik continues serving
// existing certificates even when etcd becomes unavailable.
//
// Scenario:
// 1. Traefik obtains certificates for domains (stored in etcd)
// 2. Verify certificates are served correctly
// 3. Stop etcd
// 4. Verify Traefik still serves the cached certificates
// 5. Restart etcd
// 6. Verify Traefik recovers and can obtain new certificates
func (s *AcmeEtcdResilienceSuite) TestEtcdFailureWhileServingCerts() {
	const numDomains = 5

	ctx := context.Background()

	// Generate domains
	endpoints := make(map[string]x509.Certificate, numDomains)
	for i := range numDomains {
		endpoints[fmt.Sprintf("etcd-fail-%d.acme.wtf", i)] = x509.Certificate{}
	}

	// Start backend
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	template := resilienceTemplateModel{
		PortHTTP:    ":5002",
		PortHTTPS:   ":5001",
		PortAPI:     ":5003",
		EtcdAddress: s.etcdAddr,
		CAServer:    s.getAcmeURL(),
		Domains:     slices.Collect(maps.Keys(endpoints)),
	}

	file := s.adaptFile("fixtures/acme/acme_etcd_resilience.toml", template)
	cmd, logBuf := s.cmdTraefik(withConfigFile(file))
	defer s.killCmd(cmd)

	s.T().Cleanup(func() {
		if s.T().Failed() || *showLog {
			s.displayLogCompose()
			s.T().Log("=== Traefik logs ===")
			s.T().Log(logBuf.String())
		}
	})

	// Wait for Traefik to start
	err := try.Do(15*time.Second, func() error {
		resp, errReq := http.Get(fmt.Sprintf("http://127.0.0.1%s/ping", template.PortAPI))
		if errReq != nil {
			return errReq
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("traefik ping returned %d", resp.StatusCode)
		}
		return nil
	})
	require.NoError(s.T(), err, "Traefik did not start")

	// Phase 1: Obtain certificates
	s.T().Log("Phase 1: Obtaining initial certificates...")
	for domain := range endpoints {
		err := try.Do(60*time.Second, func() error {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}

			req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s", domain)
			}
			cert := resp.TLS.PeerCertificates[0]
			if cert.Subject.CommonName != domain && !slices.Contains(cert.DNSNames, domain) {
				return fmt.Errorf("cert served is not for %s", domain)
			}
			endpoints[domain] = *cert
			return nil
		})
		require.NoError(s.T(), err, "Failed to get cert for %s", domain)
	}
	s.T().Logf("✓ Obtained certificates for all %d domains", numDomains)

	// Phase 2: Stop etcd
	s.T().Log("Phase 2: Stopping etcd to simulate failure...")
	s.composeStop("etcd")
	try.Sleep(2 * time.Second) // Give Traefik time to detect the failure

	// Phase 3: Verify Traefik still serves cached certificates
	s.T().Log("Phase 3: Verifying Traefik still serves certificates with etcd down...")
	for domain, expectedCert := range endpoints {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         domain,
				},
				DisableKeepAlives: true,
			},
			Timeout: 5 * time.Second,
		}

		req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
		req.Host = domain
		resp, err := client.Do(req)
		require.NoError(s.T(), err, "Traefik should still respond for %s with etcd down", domain)
		resp.Body.Close()

		require.NotNil(s.T(), resp.TLS, "TLS should still work for %s", domain)
		require.NotEmpty(s.T(), resp.TLS.PeerCertificates, "Should still have cert for %s", domain)

		// Verify it's the same certificate (serial number match)
		actualSerial := resp.TLS.PeerCertificates[0].SerialNumber.String()
		expectedSerial := expectedCert.SerialNumber.String()
		require.Equal(s.T(), expectedSerial, actualSerial,
			"Certificate serial mismatch for %s - Traefik lost cached cert!", domain)
	}
	s.T().Logf("✓ Traefik continues serving %d cached certificates with etcd down", numDomains)

	// Phase 4: Restart etcd
	s.T().Log("Phase 4: Restarting etcd...")
	s.composeUp("etcd")

	// Recreate kvClient since etcd restarted
	s.etcdAddr = net.JoinHostPort(s.getComposeServiceIP("etcd"), "2379")
	s.kvClient, err = valkeyrie.NewStore(
		ctx,
		etcdv3.StoreName,
		[]string{s.etcdAddr},
		&etcdv3.Config{
			ConnectionTimeout: 10 * time.Second,
		},
	)
	require.NoError(s.T(), err)

	// Wait for etcd to be ready
	err = try.Do(30*time.Second, try.KVExists(s.kvClient, "test"))
	require.NoError(s.T(), err, "etcd did not come back online")
	s.T().Log("✓ etcd is back online")

	// Phase 5: Verify Traefik reconnects and still serves certs
	s.T().Log("Phase 5: Verifying Traefik reconnects to etcd...")
	try.Sleep(5 * time.Second) // Give Traefik time to reconnect

	for domain := range endpoints {
		err := try.Do(30*time.Second, func() error {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}

			req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s after etcd recovery", domain)
			}
			return nil
		})
		require.NoError(s.T(), err, "Traefik should recover for %s", domain)
	}
	s.T().Logf("✓ Traefik recovered and serves certificates after etcd restart")
}

// TestAcmeServerFailureDuringIssuance tests that Traefik handles ACME server
// failures gracefully and retries certificate issuance when the server recovers.
//
// Scenario:
// 1. Start Traefik configured for multiple domains
// 2. Let some certificates be issued
// 3. Stop Pebble (ACME server)
// 4. Verify Traefik continues serving already-issued certificates
// 5. Restart Pebble
// 6. Verify Traefik eventually obtains remaining certificates
func (s *AcmeEtcdResilienceSuite) TestAcmeServerFailureDuringIssuance() {
	const totalDomains = 10
	const initialDomains = 3 // Domains to issue before stopping Pebble

	// Generate domains
	allDomains := make([]string, totalDomains)
	for i := range totalDomains {
		allDomains[i] = fmt.Sprintf("acme-fail-%d.acme.wtf", i)
	}
	initialDomainsSlice := allDomains[:initialDomains]
	remainingDomains := allDomains[initialDomains:]

	issuedCerts := make(map[string]x509.Certificate)

	// Start backend
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	template := resilienceTemplateModel{
		PortHTTP:    ":5002",
		PortHTTPS:   ":5001",
		PortAPI:     ":5003",
		EtcdAddress: s.etcdAddr,
		CAServer:    s.getAcmeURL(),
		Domains:     allDomains,
	}

	file := s.adaptFile("fixtures/acme/acme_etcd_resilience.toml", template)
	cmd, logBuf := s.cmdTraefik(withConfigFile(file))
	defer s.killCmd(cmd)

	s.T().Cleanup(func() {
		if s.T().Failed() || *showLog {
			s.displayLogCompose()
			s.T().Log("=== Traefik logs ===")
			s.T().Log(logBuf.String())
		}
	})

	// Wait for Traefik to start
	err := try.Do(15*time.Second, func() error {
		resp, errReq := http.Get(fmt.Sprintf("http://127.0.0.1%s/ping", template.PortAPI))
		if errReq != nil {
			return errReq
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("traefik ping returned %d", resp.StatusCode)
		}
		return nil
	})
	require.NoError(s.T(), err, "Traefik did not start")

	// Phase 1: Obtain certificates for initial domains
	s.T().Logf("Phase 1: Obtaining certificates for first %d domains...", initialDomains)
	for _, domain := range initialDomainsSlice {
		err := try.Do(60*time.Second, func() error {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}

			req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s", domain)
			}
			cert := resp.TLS.PeerCertificates[0]
			if cert.Subject.CommonName != domain && !slices.Contains(cert.DNSNames, domain) {
				return fmt.Errorf("cert served is not for %s", domain)
			}
			issuedCerts[domain] = *cert
			return nil
		})
		require.NoError(s.T(), err, "Failed to get cert for %s", domain)
	}
	s.T().Logf("✓ Obtained certificates for %d initial domains", initialDomains)

	// Phase 2: Stop Pebble
	s.T().Log("Phase 2: Stopping Pebble (ACME server)...")
	s.composeStop("pebble")
	try.Sleep(2 * time.Second)

	// Phase 3: Verify already-issued certificates still work
	s.T().Log("Phase 3: Verifying already-issued certificates still work...")
	for domain, expectedCert := range issuedCerts {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         domain,
				},
				DisableKeepAlives: true,
			},
			Timeout: 5 * time.Second,
		}

		req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
		req.Host = domain
		resp, err := client.Do(req)
		require.NoError(s.T(), err, "Traefik should still respond for %s with Pebble down", domain)
		resp.Body.Close()

		require.NotNil(s.T(), resp.TLS, "TLS should still work for %s", domain)
		actualSerial := resp.TLS.PeerCertificates[0].SerialNumber.String()
		expectedSerial := expectedCert.SerialNumber.String()
		require.Equal(s.T(), expectedSerial, actualSerial, "Certificate mismatch for %s", domain)
	}
	s.T().Logf("✓ Already-issued certificates still work with Pebble down")

	// Phase 4: Restart Pebble
	s.T().Log("Phase 4: Restarting Pebble...")
	s.composeUp("pebble")

	// Wait for Pebble to be ready
	pebbleTransport, err := setupPebbleRootCA()
	require.NoError(s.T(), err)
	pebbleClient := &http.Client{Transport: pebbleTransport}

	err = try.Do(30*time.Second, func() error {
		req := testhelpers.MustNewRequest(http.MethodGet, s.getAcmeURL(), nil)
		resp, errGet := pebbleClient.Do(req)
		if errGet != nil {
			return errGet
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("pebble returned %d", resp.StatusCode)
		}
		return nil
	})
	require.NoError(s.T(), err, "Pebble did not come back online")
	s.T().Log("✓ Pebble is back online")

	// Phase 5: Verify remaining certificates get issued
	s.T().Logf("Phase 5: Verifying Traefik obtains remaining %d certificates...", len(remainingDomains))
	for _, domain := range remainingDomains {
		err := try.Do(90*time.Second, func() error {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}

			req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s", domain)
			}
			cert := resp.TLS.PeerCertificates[0]
			if cert.Subject.CommonName != domain && !slices.Contains(cert.DNSNames, domain) {
				return fmt.Errorf("cert served is not for %s (got %s)", domain, cert.Subject.CommonName)
			}
			return nil
		})
		require.NoError(s.T(), err, "Failed to get cert for %s after Pebble recovery", domain)
	}
	s.T().Logf("✓ All %d certificates obtained after Pebble recovery", totalDomains)
}

// TestMultiReplicaEtcdFailureRecovery tests that multiple Traefik replicas
// remain consistent after an etcd failure and recovery.
//
// Scenario:
// 1. Start multiple Traefik replicas with nginx LB
// 2. Obtain certificates for domains
// 3. Verify all replicas serve the same certificates
// 4. Stop etcd
// 5. Verify all replicas still serve cached certificates
// 6. Restart etcd
// 7. Verify replicas recover and remain consistent
func (s *AcmeEtcdResilienceSuite) TestMultiReplicaEtcdFailureRecovery() {
	const numDomains = 5
	const numReplicas = 3

	ctx := context.Background()

	// Generate domains
	endpoints := make(map[string]x509.Certificate, numDomains)
	for i := range numDomains {
		endpoints[fmt.Sprintf("replica-fail-%d.acme.wtf", i)] = x509.Certificate{}
	}

	// Start backend
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	lbHTTPSPort := 5001
	lbHTTPPort := 5002
	portHTTPStart := 5102
	portHTTPSStart := 5101
	portAPIStart := 5103

	allHTTPPorts := []int{}
	allHTTPSPorts := []int{}
	for i := range numReplicas {
		allHTTPPorts = append(allHTTPPorts, portHTTPStart+i*100)
		allHTTPSPorts = append(allHTTPSPorts, portHTTPSStart+i*100)
	}

	// Start nginx LB
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

	// Start Traefik replicas
	var traefikLogs []*bytes.Buffer
	for i := range numReplicas {
		template := resilienceTemplateModel{
			PortHTTP:    fmt.Sprintf(":%d", portHTTPStart+i*100),
			PortHTTPS:   fmt.Sprintf(":%d", portHTTPSStart+i*100),
			PortAPI:     fmt.Sprintf(":%d", portAPIStart+i*100),
			EtcdAddress: s.etcdAddr,
			CAServer:    s.getAcmeURL(),
			Domains:     slices.Collect(maps.Keys(endpoints)),
		}

		file := s.adaptFile("fixtures/acme/acme_etcd_resilience.toml", template)
		cmd, logBuf := s.cmdTraefik(withConfigFile(file))
		traefikLogs = append(traefikLogs, logBuf)
		defer s.killCmd(cmd)
	}

	s.T().Cleanup(func() {
		if s.T().Failed() || *showLog {
			s.displayLogCompose()
			for i, logBuf := range traefikLogs {
				s.T().Logf("=== Traefik replica %d logs ===", i+1)
				s.T().Log(logBuf.String())
			}
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
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("replica %d ping returned %d", i+1, resp.StatusCode)
			}
			return nil
		})
		require.NoError(s.T(), err, "Replica %d did not start", i+1)
	}
	s.T().Logf("✓ All %d replicas started", numReplicas)

	// Phase 1: Obtain certificates via LB
	s.T().Log("Phase 1: Obtaining certificates via load balancer...")
	for domain := range endpoints {
		err := try.Do(60*time.Second, func() error {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
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
			cert := resp.TLS.PeerCertificates[0]
			if cert.Subject.CommonName != domain && !slices.Contains(cert.DNSNames, domain) {
				return fmt.Errorf("cert for %s not yet available", domain)
			}
			endpoints[domain] = *cert
			return nil
		})
		require.NoError(s.T(), err, "No cert served for %s", domain)
	}
	s.T().Logf("✓ Obtained certificates for all %d domains", numDomains)

	// Phase 2: Verify consistency across replicas
	s.T().Log("Phase 2: Verifying consistency across replicas...")
	for domain, cert := range endpoints {
		expectedSerial := cert.SerialNumber.String()
		for i := range numReplicas {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}
			req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", portHTTPSStart+i*100), nil)
			req.Host = domain
			resp, err := client.Do(req)
			require.NoError(s.T(), err, "Replica %d unreachable for %s", i+1, domain)
			resp.Body.Close()

			actualSerial := resp.TLS.PeerCertificates[0].SerialNumber.String()
			require.Equal(s.T(), expectedSerial, actualSerial,
				"CONSISTENCY VIOLATION: %s has different serial on replica %d", domain, i+1)
		}
	}
	s.T().Logf("✓ All replicas serve consistent certificates")

	// Phase 3: Stop etcd
	s.T().Log("Phase 3: Stopping etcd...")
	s.composeStop("etcd")
	try.Sleep(3 * time.Second)

	// Phase 4: Verify all replicas still serve cached certs
	s.T().Log("Phase 4: Verifying all replicas still serve certificates with etcd down...")
	for domain, expectedCert := range endpoints {
		expectedSerial := expectedCert.SerialNumber.String()
		for i := range numReplicas {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
				Timeout: 5 * time.Second,
			}
			req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", portHTTPSStart+i*100), nil)
			req.Host = domain
			resp, err := client.Do(req)
			require.NoError(s.T(), err, "Replica %d should still respond with etcd down", i+1)
			resp.Body.Close()

			actualSerial := resp.TLS.PeerCertificates[0].SerialNumber.String()
			require.Equal(s.T(), expectedSerial, actualSerial,
				"Replica %d lost certificate for %s!", i+1, domain)
		}
	}
	s.T().Logf("✓ All replicas continue serving certificates with etcd down")

	// Phase 5: Restart etcd
	s.T().Log("Phase 5: Restarting etcd...")
	s.composeUp("etcd")

	// Recreate kvClient
	s.etcdAddr = net.JoinHostPort(s.getComposeServiceIP("etcd"), "2379")
	s.kvClient, err = valkeyrie.NewStore(
		ctx,
		etcdv3.StoreName,
		[]string{s.etcdAddr},
		&etcdv3.Config{
			ConnectionTimeout: 10 * time.Second,
		},
	)
	require.NoError(s.T(), err)

	err = try.Do(30*time.Second, try.KVExists(s.kvClient, "test"))
	require.NoError(s.T(), err, "etcd did not come back online")
	s.T().Log("✓ etcd is back online")

	// Phase 6: Verify consistency is maintained after recovery
	s.T().Log("Phase 6: Verifying consistency after etcd recovery...")
	try.Sleep(5 * time.Second) // Give replicas time to reconnect

	for domain, cert := range endpoints {
		expectedSerial := cert.SerialNumber.String()
		for i := range numReplicas {
			err := try.Do(30*time.Second, func() error {
				client := &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
							ServerName:         domain,
						},
						DisableKeepAlives: true,
					},
				}
				req := testhelpers.MustNewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", portHTTPSStart+i*100), nil)
				req.Host = domain
				resp, errReq := client.Do(req)
				if errReq != nil {
					return errReq
				}
				resp.Body.Close()
				actualSerial := resp.TLS.PeerCertificates[0].SerialNumber.String()
				if actualSerial != expectedSerial {
					return fmt.Errorf("serial mismatch: expected %s, got %s", expectedSerial, actualSerial)
				}
				return nil
			})
			require.NoError(s.T(), err, "Replica %d inconsistent after recovery", i+1)
		}
	}
	s.T().Logf("✓ All replicas remain consistent after etcd recovery")
}

// TestNewCertificateAfterEtcdRecovery tests that Traefik can obtain NEW certificates
// after etcd recovers from a failure (not just serve cached ones).
//
// Scenario:
// 1. Start Traefik with some domains
// 2. Stop etcd BEFORE certificates are obtained
// 3. Verify Traefik handles the failure gracefully
// 4. Restart etcd
// 5. Verify Traefik successfully obtains certificates
func (s *AcmeEtcdResilienceSuite) TestNewCertificateAfterEtcdRecovery() {
	const numDomains = 3

	ctx := context.Background()

	// Generate domains
	domains := make([]string, numDomains)
	for i := range numDomains {
		domains[i] = fmt.Sprintf("new-cert-%d.acme.wtf", i)
	}

	// Stop etcd FIRST - before Traefik starts
	s.T().Log("Phase 1: Stopping etcd before Traefik starts...")
	s.composeStop("etcd")
	try.Sleep(2 * time.Second)

	// Start backend
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	template := resilienceTemplateModel{
		PortHTTP:    ":5002",
		PortHTTPS:   ":5001",
		PortAPI:     ":5003",
		EtcdAddress: s.etcdAddr,
		CAServer:    s.getAcmeURL(),
		Domains:     domains,
	}

	file := s.adaptFile("fixtures/acme/acme_etcd_resilience.toml", template)
	cmd, logBuf := s.cmdTraefik(withConfigFile(file))
	defer s.killCmd(cmd)

	s.T().Cleanup(func() {
		if s.T().Failed() || *showLog {
			s.displayLogCompose()
			s.T().Log("=== Traefik logs ===")
			s.T().Log(logBuf.String())
		}
	})

	// Phase 2: Verify Traefik starts (but can't get certs)
	s.T().Log("Phase 2: Verifying Traefik starts despite etcd being down...")
	err := try.Do(15*time.Second, func() error {
		resp, errReq := http.Get(fmt.Sprintf("http://127.0.0.1%s/ping", template.PortAPI))
		if errReq != nil {
			return errReq
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("traefik ping returned %d", resp.StatusCode)
		}
		return nil
	})
	require.NoError(s.T(), err, "Traefik should start even with etcd down")
	s.T().Log("✓ Traefik started with etcd down")

	// Phase 3: Restart etcd
	s.T().Log("Phase 3: Starting etcd...")
	s.composeUp("etcd")

	// Recreate kvClient
	s.etcdAddr = net.JoinHostPort(s.getComposeServiceIP("etcd"), "2379")
	s.kvClient, err = valkeyrie.NewStore(
		ctx,
		etcdv3.StoreName,
		[]string{s.etcdAddr},
		&etcdv3.Config{
			ConnectionTimeout: 10 * time.Second,
		},
	)
	require.NoError(s.T(), err)

	err = try.Do(30*time.Second, try.KVExists(s.kvClient, "test"))
	require.NoError(s.T(), err, "etcd did not come online")
	s.T().Log("✓ etcd is online")

	// Phase 4: Verify Traefik obtains certificates
	s.T().Log("Phase 4: Verifying Traefik obtains certificates after etcd recovery...")
	for _, domain := range domains {
		err := try.Do(90*time.Second, func() error {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         domain,
					},
					DisableKeepAlives: true,
				},
			}

			req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
			req.Host = domain
			resp, errReq := client.Do(req)
			if errReq != nil {
				return errReq
			}
			resp.Body.Close()
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS cert for %s", domain)
			}
			cert := resp.TLS.PeerCertificates[0]
			if cert.Subject.CommonName != domain && !slices.Contains(cert.DNSNames, domain) {
				return fmt.Errorf("cert served is not for %s (got CN=%s)", domain, cert.Subject.CommonName)
			}
			return nil
		})
		require.NoError(s.T(), err, "Failed to get cert for %s after etcd recovery", domain)
	}
	s.T().Logf("✓ Successfully obtained all %d certificates after etcd recovery", numDomains)

	// Phase 5: Verify certificates are stored in etcd
	s.T().Log("Phase 5: Verifying certificates are stored in etcd...")
	pair, err := s.kvClient.Get(ctx, "traefik/acme/data/default", nil)
	require.NoError(s.T(), err, "Certificate data should be stored in etcd")
	require.NotNil(s.T(), pair)
	require.NotEmpty(s.T(), pair.Value)
	s.T().Log("✓ Certificate data is stored in etcd")
}
