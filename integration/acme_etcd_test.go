package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kvtools/etcdv3"
	"github.com/kvtools/valkeyrie"
	"github.com/kvtools/valkeyrie/store"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/traefik/traefik/v3/integration/try"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/provider/acme"
	"github.com/traefik/traefik/v3/pkg/testhelpers"
)

// AcmeEtcdSuite tests distributed ACME storage with etcd backend.
type AcmeEtcdSuite struct {
	BaseSuite

	pebbleIP      string
	etcdAddr      string
	kvClient      store.Store
	fakeDNSServer *dns.Server
}

func TestAcmeEtcdSuite(t *testing.T) {
	suite.Run(t, new(AcmeEtcdSuite))
}

type acmeEtcdTestCase struct {
	template            acmeEtcdTemplateModel
	traefikConfFilePath string
	expectedDomain      string
}

type acmeEtcdTemplateModel struct {
	PortHTTP    string
	PortHTTPS   string
	EtcdAddress string
	LockTimeout string
	Acme        map[string]static.CertificateResolver
}

func (s *AcmeEtcdSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	s.createComposeProject("acme_etcd")
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
	err = try.Do(60*time.Second, try.KVExists(s.kvClient, "test"))
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

func (s *AcmeEtcdSuite) TearDownSuite() {
	s.BaseSuite.TearDownSuite()

	if s.fakeDNSServer != nil {
		err := s.fakeDNSServer.Shutdown()
		if err != nil {
			log.Info().Msg(err.Error())
		}
	}

	s.composeDown()
}

func (s *AcmeEtcdSuite) TearDownTest() {
	// Clean up etcd data between tests
	ctx := context.Background()
	_ = s.kvClient.DeleteTree(ctx, "traefik/acme")
}

// TestHTTP01WithEtcdStorage verifies basic certificate issuance with etcd storage.
func (s *AcmeEtcdSuite) TestHTTP01WithEtcdStorage() {
	testCase := acmeEtcdTestCase{
		traefikConfFilePath: "fixtures/acme/acme_etcd.toml",
		expectedDomain:      acmeDomain,
		template: acmeEtcdTemplateModel{
			EtcdAddress: s.etcdAddr,
			Acme: map[string]static.CertificateResolver{
				"default": {ACME: &acme.Configuration{
					HTTPChallenge: &acme.HTTPChallenge{EntryPoint: "web"},
				}},
			},
		},
	}

	s.retrieveAcmeCertificateWithEtcd(testCase)

	// Verify certificate data is stored in etcd
	s.verifyCertificateStoredInEtcd("default", acmeDomain)
}

// TestTLSALPN01WithEtcdStorage verifies TLS-ALPN-01 challenge with etcd storage.
func (s *AcmeEtcdSuite) TestTLSALPN01WithEtcdStorage() {
	testCase := acmeEtcdTestCase{
		traefikConfFilePath: "fixtures/acme/acme_etcd.toml",
		expectedDomain:      acmeDomain,
		template: acmeEtcdTemplateModel{
			EtcdAddress: s.etcdAddr,
			Acme: map[string]static.CertificateResolver{
				"default": {ACME: &acme.Configuration{
					TLSChallenge: &acme.TLSChallenge{},
				}},
			},
		},
	}

	s.retrieveAcmeCertificateWithEtcd(testCase)

	// Verify certificate data is stored in etcd
	s.verifyCertificateStoredInEtcd("default", acmeDomain)
}

// TestAccountPersistenceInEtcd verifies ACME account is stored and retrieved from etcd.
func (s *AcmeEtcdSuite) TestAccountPersistenceInEtcd() {
	template := acmeEtcdTemplateModel{
		PortHTTP:    ":5002",
		PortHTTPS:   ":5001",
		EtcdAddress: s.etcdAddr,
		Acme: map[string]static.CertificateResolver{
			"default": {ACME: &acme.Configuration{
				HTTPChallenge: &acme.HTTPChallenge{EntryPoint: "web"},
				CAServer:      s.getAcmeURL(),
			}},
		},
	}

	file := s.adaptFile("fixtures/acme/acme_etcd.toml", template)
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	s.traefikCmd(withConfigFile(file))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Wait for certificate to be obtained
	err := try.Do(60*time.Second, func() error {
		_, errGet := client.Get("https://127.0.0.1:5001")
		return errGet
	})
	require.NoError(s.T(), err)

	// Verify account is stored in etcd
	ctx := context.Background()
	pair, err := s.kvClient.Get(ctx, "traefik/acme/data/default", nil)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), pair)
	require.NotEmpty(s.T(), pair.Value)

	// The data is gzip compressed, verify it's not empty
	assert.NotEmpty(s.T(), pair.Value)
}

// TestEtcdConnectionFailureFallback verifies graceful degradation when etcd is unavailable.
func (s *AcmeEtcdSuite) TestEtcdConnectionFailureFallback() {
	// Use a non-existent etcd address
	template := acmeEtcdTemplateModel{
		PortHTTP:    ":5002",
		PortHTTPS:   ":5001",
		EtcdAddress: "127.0.0.1:29999", // Invalid address
		Acme: map[string]static.CertificateResolver{
			"default": {ACME: &acme.Configuration{
				HTTPChallenge: &acme.HTTPChallenge{EntryPoint: "web"},
				CAServer:      s.getAcmeURL(),
			}},
		},
	}

	file := s.adaptFile("fixtures/acme/acme_etcd.toml", template)

	// Should still start (with error logged) - Traefik doesn't crash on bad KV config
	cmd, out := s.cmdTraefik(withConfigFile(file))
	defer s.killCmd(cmd)

	// Wait a bit for startup
	time.Sleep(3 * time.Second)

	// Verify Traefik started (API should be accessible)
	err := try.GetRequest("http://127.0.0.1:8080/api/rawdata", 5*time.Second, try.StatusCodeIs(http.StatusOK))
	require.NoError(s.T(), err)

	// Verify error was logged about etcd connection
	assert.Contains(s.T(), out.String(), "etcd")
}

// TestDistributedLockingWithMultipleDomains verifies locking works correctly
// when requesting certificates for multiple domains.
func (s *AcmeEtcdSuite) TestDistributedLockingWithMultipleDomains() {
	template := acmeEtcdTemplateModel{
		PortHTTP:    ":5002",
		PortHTTPS:   ":5001",
		EtcdAddress: s.etcdAddr,
		LockTimeout: "30s",
		Acme: map[string]static.CertificateResolver{
			"default": {ACME: &acme.Configuration{
				HTTPChallenge: &acme.HTTPChallenge{EntryPoint: "web"},
				CAServer:      s.getAcmeURL(),
			}},
		},
	}

	file := s.adaptFile("fixtures/acme/acme_etcd_distributed.toml", template)
	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	s.traefikCmd(withConfigFile(file))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	// Request certificates for both domains
	domains := []string{"traefik.acme.wtf", "traefik2.acme.wtf"}

	for _, domain := range domains {
		err := try.Do(60*time.Second, func() error {
			req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
			req.Host = domain
			resp, errGet := client.Do(req)
			if errGet != nil {
				return errGet
			}
			if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
				return fmt.Errorf("no TLS certificate for %s", domain)
			}
			return nil
		})
		require.NoError(s.T(), err)
	}

	// Verify both certificates are stored in etcd
	s.verifyCertificateStoredInEtcd("default", "traefik.acme.wtf")
	s.verifyCertificateStoredInEtcd("default", "traefik2.acme.wtf")
}

func (s *AcmeEtcdSuite) getAcmeURL() string {
	return fmt.Sprintf("https://%s/dir", net.JoinHostPort(s.pebbleIP, "14000"))
}

// retrieveAcmeCertificateWithEtcd handles the common certificate retrieval logic.
func (s *AcmeEtcdSuite) retrieveAcmeCertificateWithEtcd(testCase acmeEtcdTestCase) {
	if len(testCase.template.PortHTTP) == 0 {
		testCase.template.PortHTTP = ":5002"
	}
	if len(testCase.template.PortHTTPS) == 0 {
		testCase.template.PortHTTPS = ":5001"
	}

	for _, value := range testCase.template.Acme {
		if len(value.ACME.CAServer) == 0 {
			value.ACME.CAServer = s.getAcmeURL()
		}
	}

	file := s.adaptFile(testCase.traefikConfFilePath, testCase.template)
	s.traefikCmd(withConfigFile(file))

	backend := startTestServer("9010", http.StatusOK, "")
	defer backend.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Wait for traefik to start
	err := try.Do(60*time.Second, func() error {
		_, errGet := client.Get("https://127.0.0.1:5001")
		return errGet
	})
	require.NoError(s.T(), err)

	// Verify certificate
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         testCase.expectedDomain,
			},
			DisableKeepAlives: true,
		},
	}

	req := testhelpers.MustNewRequest(http.MethodGet, "https://127.0.0.1:5001/", nil)
	req.Host = testCase.expectedDomain

	var gotDomains []string
	err = try.Do(60*time.Second, func() error {
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			return errors.New("no TLS certificate")
		}
		gotDomains = append(gotDomains, resp.TLS.PeerCertificates[0].Subject.CommonName)
		gotDomains = append(gotDomains, resp.TLS.PeerCertificates[0].DNSNames...)

		if !slices.Contains(gotDomains, testCase.expectedDomain) {
			return fmt.Errorf("domain %s not found in %v", testCase.expectedDomain, gotDomains)
		}
		return nil
	})

	require.NoError(s.T(), err)
	assert.Contains(s.T(), gotDomains, testCase.expectedDomain)
}

// verifyCertificateStoredInEtcd checks that certificate data exists in etcd.
func (s *AcmeEtcdSuite) verifyCertificateStoredInEtcd(resolverName, expectedDomain string) {
	ctx := context.Background()
	key := fmt.Sprintf("traefik/acme/data/%s", resolverName)

	// Wait for data containing the expected domain to appear - CI can be slow
	err := try.Do(60*time.Second, func() error {
		pair, errGet := s.kvClient.Get(ctx, key, nil)
		if errGet != nil {
			return errGet
		}
		if pair == nil || len(pair.Value) == 0 {
			return fmt.Errorf("no data found for key %s", key)
		}

		// Data is gzip compressed, try to decompress
		decompressed, errDecompress := decompressForTest(pair.Value)
		if errDecompress != nil {
			// Might be uncompressed
			decompressed = pair.Value
		}

		// Simple check: the domain should appear in the JSON data
		if !strings.Contains(string(decompressed), expectedDomain) {
			return fmt.Errorf("domain %s not yet found in stored data", expectedDomain)
		}

		return nil
	})
	require.NoError(s.T(), err, "Certificate for %s not found in etcd", expectedDomain)
}

func decompressForTest(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}
