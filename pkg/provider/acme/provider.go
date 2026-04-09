package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	httpmuxer "github.com/traefik/traefik/v3/pkg/muxer/http"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/safe"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
	"github.com/traefik/traefik/v3/pkg/version"
)

const resolverSuffix = ".acme"

// Configuration holds ACME configuration provided by users.
type Configuration struct {
	Email                string   `description:"Email address used for registration." json:"email,omitempty" toml:"email,omitempty" yaml:"email,omitempty"`
	CAServer             string   `description:"CA server to use." json:"caServer,omitempty" toml:"caServer,omitempty" yaml:"caServer,omitempty"`
	PreferredChain       string   `description:"Preferred chain to use." json:"preferredChain,omitempty" toml:"preferredChain,omitempty" yaml:"preferredChain,omitempty" export:"true"`
	Profile              string   `description:"Certificate profile to use." json:"profile,omitempty" toml:"profile,omitempty" yaml:"profile,omitempty" export:"true"`
	EmailAddresses       []string `description:"CSR email addresses to use." json:"emailAddresses,omitempty" toml:"emailAddresses,omitempty" yaml:"emailAddresses,omitempty"`
	DisableCommonName    bool     `description:"Disable the common name in the CSR." json:"disableCommonName,omitempty" toml:"disableCommonName,omitempty" yaml:"disableCommonName,omitempty" export:"true"`
	Storage              string   `description:"Storage to use (file path or empty if using kvStore)." json:"storage,omitempty" toml:"storage,omitempty" yaml:"storage,omitempty" export:"true"`
	KeyType              string   `description:"KeyType used for generating certificate private key. Allow value 'EC256', 'EC384', 'RSA2048', 'RSA4096', 'RSA8192'." json:"keyType,omitempty" toml:"keyType,omitempty" yaml:"keyType,omitempty" export:"true"`
	EAB                  *EAB     `description:"External Account Binding to use." json:"eab,omitempty" toml:"eab,omitempty" yaml:"eab,omitempty"`
	CertificatesDuration int      `description:"Certificates' duration in hours." json:"certificatesDuration,omitempty" toml:"certificatesDuration,omitempty" yaml:"certificatesDuration,omitempty" export:"true"`

	ClientTimeout               ptypes.Duration `description:"Timeout for a complete HTTP transaction with the ACME server." json:"clientTimeout,omitempty" toml:"clientTimeout,omitempty" yaml:"clientTimeout,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
	ClientResponseHeaderTimeout ptypes.Duration `description:"Timeout for receiving the response headers when communicating with the ACME server." json:"clientResponseHeaderTimeout,omitempty" toml:"clientResponseHeaderTimeout,omitempty" yaml:"clientResponseHeaderTimeout,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`

	CACertificates   []string `description:"Specify the paths to PEM encoded CA Certificates that can be used to authenticate an ACME server with an HTTPS certificate not issued by a CA in the system-wide trusted root list." json:"caCertificates,omitempty" toml:"caCertificates,omitempty" yaml:"caCertificates,omitempty"`
	CASystemCertPool bool     `description:"Define if the certificates pool must use a copy of the system cert pool." json:"caSystemCertPool,omitempty" toml:"caSystemCertPool,omitempty" yaml:"caSystemCertPool,omitempty" export:"true"`
	CAServerName     string   `description:"Specify the CA server name that can be used to authenticate an ACME server with an HTTPS certificate not issued by a CA in the system-wide trusted root list." json:"caServerName,omitempty" toml:"caServerName,omitempty" yaml:"caServerName,omitempty" export:"true"`

	DNSChallenge  *DNSChallenge  `description:"Activate DNS-01 Challenge." json:"dnsChallenge,omitempty" toml:"dnsChallenge,omitempty" yaml:"dnsChallenge,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
	HTTPChallenge *HTTPChallenge `description:"Activate HTTP-01 Challenge." json:"httpChallenge,omitempty" toml:"httpChallenge,omitempty" yaml:"httpChallenge,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
	TLSChallenge  *TLSChallenge  `description:"Activate TLS-ALPN-01 Challenge." json:"tlsChallenge,omitempty" toml:"tlsChallenge,omitempty" yaml:"tlsChallenge,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`

	// Distributed KV storage options (replaces file storage when configured)
	Etcd *EtcdStoreConfig `description:"Use etcd for distributed ACME certificate storage." json:"etcd,omitempty" toml:"etcd,omitempty" yaml:"etcd,omitempty" label:"allowEmpty" file:"allowEmpty" export:"true"`
}

// SetDefaults sets the default values.
func (a *Configuration) SetDefaults() {
	a.CAServer = lego.LEDirectoryProduction
	a.Storage = "acme.json"
	a.KeyType = "RSA4096"
	a.CertificatesDuration = 3 * 30 * 24 // 90 Days
	a.ClientTimeout = ptypes.Duration(2 * time.Minute)
	a.ClientResponseHeaderTimeout = ptypes.Duration(30 * time.Second)
}

// CertAndStore allows mapping a TLS certificate to a TLS store.
type CertAndStore struct {
	Certificate
	Store string `json:"Store"`
}

// Certificate is a struct which contains all data needed from an ACME certificate.
type Certificate struct {
	Domain      types.Domain `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
	Certificate []byte       `json:"certificate,omitempty" toml:"certificate,omitempty" yaml:"certificate,omitempty"`
	Key         []byte       `json:"key,omitempty" toml:"key,omitempty" yaml:"key,omitempty"`
}

// EAB contains External Account Binding configuration.
type EAB struct {
	Kid         string `description:"Key identifier from External CA." json:"kid,omitempty" toml:"kid,omitempty" yaml:"kid,omitempty" loggable:"false"`
	HmacEncoded string `description:"Base64 encoded HMAC key from External CA." json:"hmacEncoded,omitempty" toml:"hmacEncoded,omitempty" yaml:"hmacEncoded,omitempty" loggable:"false"`
}

// DNSChallenge contains DNS challenge configuration.
type DNSChallenge struct {
	Provider    string       `description:"Use a DNS-01 based challenge provider rather than HTTPS." json:"provider,omitempty" toml:"provider,omitempty" yaml:"provider,omitempty" export:"true"`
	Resolvers   []string     `description:"Use following DNS servers to resolve the FQDN authority." json:"resolvers,omitempty" toml:"resolvers,omitempty" yaml:"resolvers,omitempty"`
	Propagation *Propagation `description:"DNS propagation checks configuration" json:"propagation,omitempty" toml:"propagation,omitempty" yaml:"propagation,omitempty"  label:"allowEmpty" file:"allowEmpty" export:"true"`

	// Deprecated: please use Propagation.DelayBeforeChecks instead.
	DelayBeforeCheck ptypes.Duration `description:"(Deprecated) Assume DNS propagates after a delay in seconds rather than finding and querying nameservers." json:"delayBeforeCheck,omitempty" toml:"delayBeforeCheck,omitempty" yaml:"delayBeforeCheck,omitempty" export:"true"`
	// Deprecated: please use Propagation.DisableChecks instead.
	DisablePropagationCheck bool `description:"(Deprecated) Disable the DNS propagation checks before notifying ACME that the DNS challenge is ready. [not recommended]" json:"disablePropagationCheck,omitempty" toml:"disablePropagationCheck,omitempty" yaml:"disablePropagationCheck,omitempty" export:"true"`
}

type Propagation struct {
	DisableChecks     bool            `description:"Disables the challenge TXT record propagation checks (not recommended)." json:"disableChecks,omitempty" toml:"disableChecks,omitempty" yaml:"disableChecks,omitempty" export:"true"`
	DisableANSChecks  bool            `description:"Disables the challenge TXT record propagation checks against authoritative nameservers." json:"disableANSChecks,omitempty" toml:"disableANSChecks,omitempty" yaml:"disableANSChecks,omitempty" export:"true"`
	RequireAllRNS     bool            `description:"Requires the challenge TXT record to be propagated to all recursive nameservers." json:"requireAllRNS,omitempty" toml:"requireAllRNS,omitempty" yaml:"requireAllRNS,omitempty" export:"true"`
	DelayBeforeChecks ptypes.Duration `description:"Defines the delay before checking the challenge TXT record propagation." json:"delayBeforeChecks,omitempty" toml:"delayBeforeChecks,omitempty" yaml:"delayBeforeChecks,omitempty" export:"true"`
}

// HTTPChallenge contains HTTP challenge configuration.
type HTTPChallenge struct {
	EntryPoint string          `description:"HTTP challenge EntryPoint" json:"entryPoint,omitempty" toml:"entryPoint,omitempty" yaml:"entryPoint,omitempty" export:"true"`
	Delay      ptypes.Duration `description:"Delay between the creation of the challenge and the validation." json:"delay,omitempty" toml:"delay,omitempty" yaml:"delay,omitempty" export:"true"`
}

// TLSChallenge contains TLS challenge configuration.
type TLSChallenge struct {
	Delay ptypes.Duration `description:"Delay between the creation of the challenge and the validation." json:"delay,omitempty" toml:"delay,omitempty" yaml:"delay,omitempty" export:"true"`
}

// Provider holds configurations of the provider.
type Provider struct {
	*Configuration
	ResolverName string
	Store        Store `json:"store,omitempty" toml:"store,omitempty" yaml:"store,omitempty"`

	TLSChallengeProvider  challenge.Provider
	HTTPChallengeProvider challenge.Provider

	certificates   []*CertAndStore
	certificatesMu sync.RWMutex

	account                *Account
	client                 *lego.Client
	configurationChan      chan<- dynamic.Message
	tlsManager             *traefiktls.Manager
	clientMutex            sync.Mutex
	configFromListenerChan chan dynamic.Configuration
	pool                   *safe.Pool
	resolvingDomains       map[string]struct{}
	resolvingDomainsMutex  sync.RWMutex

	// lastConfig stores the most recent dynamic configuration received via
	// ListenConfiguration. It is re-sent to configFromListenerChan when
	// the distributed store reconnects so that resolveNewCertificates can
	// retry domains that failed while the KV backend was unavailable.
	lastConfig   *dynamic.Configuration
	lastConfigMu sync.RWMutex

	// httpChallengeReady is closed when the acme-http@internal router is registered,
	// signaling that HTTP-01 challenge validation requests can be handled.
	httpChallengeReady     chan struct{}
	httpChallengeReadyOnce sync.Once
}

// SetTLSManager sets the tls manager to use.
func (p *Provider) SetTLSManager(tlsManager *traefiktls.Manager) {
	p.tlsManager = tlsManager
}

// SetConfigListenerChan initializes the configFromListenerChan.
func (p *Provider) SetConfigListenerChan(configFromListenerChan chan dynamic.Configuration) {
	p.configFromListenerChan = configFromListenerChan
}

// ListenConfiguration sets a new Configuration into the configFromListenerChan.
func (p *Provider) ListenConfiguration(config dynamic.Configuration) {
	// Signal HTTP challenge readiness when the acme-http@internal router is registered.
	// This ensures renewal doesn't start before the challenge endpoint can handle requests.
	if p.HTTPChallenge != nil && config.HTTP != nil && config.HTTP.Routers != nil {
		if _, ok := config.HTTP.Routers["acme-http@internal"]; ok {
			p.httpChallengeReadyOnce.Do(func() {
				close(p.httpChallengeReady)
			})
		}
	}

	// Store a snapshot so watchDistributedStore can re-trigger domain
	// resolution after a KV backend reconnection (bypassing the server's
	// config deduplication).
	cfgCopy := config
	p.lastConfigMu.Lock()
	p.lastConfig = &cfgCopy
	p.lastConfigMu.Unlock()

	p.configFromListenerChan <- config
}

// Init inits the provider.
func (p *Provider) Init() error {
	logger := log.With().Str(logs.ProviderName, p.ResolverName+resolverSuffix).Logger()

	// Initialize HTTP challenge readiness channel
	p.httpChallengeReady = make(chan struct{})

	// Storage path is only required if not using a distributed KV store
	if len(p.Configuration.Storage) == 0 && p.Configuration.Etcd == nil {
		return errors.New("unable to initialize ACME provider with no storage location for the certificates")
	}

	if p.CertificatesDuration < 1 {
		return errors.New("cannot manage certificates with duration lower than 1 hour")
	}

	if p.ClientTimeout < p.ClientResponseHeaderTimeout {
		return errors.New("clientTimeout must be at least clientResponseHeaderTimeout")
	}

	var err error
	p.account, err = p.Store.GetAccount(p.ResolverName)
	if err != nil {
		return fmt.Errorf("unable to get ACME account: %w", err)
	}

	// Reset Account if caServer changed, thus registration URI can be updated
	if p.account != nil && p.account.Registration != nil && !isAccountMatchingCaServer(logger.WithContext(context.Background()), p.account.Registration.URI, p.CAServer) {
		logger.Info().Msg("Account URI does not match the current CAServer. The account will be reset.")
		p.account = nil
	}

	p.certificatesMu.Lock()
	p.certificates, err = p.Store.GetCertificates(p.ResolverName)
	logger.Debug().Msgf("Loaded %d certificates from store at startup", len(p.certificates))
	for _, cert := range p.certificates {
		logger.Debug().Msgf("Startup cert: domains=%v", cert.Domain.ToStrArray())
	}
	p.certificatesMu.Unlock()

	if err != nil {
		return fmt.Errorf("unable to get ACME certificates : %w", err)
	}

	// Init the currently resolved domain map
	p.resolvingDomains = make(map[string]struct{})

	return nil
}

func isAccountMatchingCaServer(ctx context.Context, accountURI, serverURI string) bool {
	logger := log.Ctx(ctx)

	aru, err := url.Parse(accountURI)
	if err != nil {
		logger.Info().Err(err).Str("registrationURL", accountURI).Msg("Unable to parse account.Registration URL")
		return false
	}

	cau, err := url.Parse(serverURI)
	if err != nil {
		logger.Info().Err(err).Str("caServerURL", serverURI).Msg("Unable to parse CAServer URL")
		return false
	}

	return cau.Hostname() == aru.Hostname()
}

// ThrottleDuration returns the throttle duration.
func (p *Provider) ThrottleDuration() time.Duration {
	return 0
}

// Provide allows the file provider to provide configurations to traefik
// using the given Configuration channel.
func (p *Provider) Provide(configurationChan chan<- dynamic.Message, pool *safe.Pool) error {
	logger := log.With().Str(logs.ProviderName, p.ResolverName+resolverSuffix).Str("acmeCA", p.Configuration.CAServer).
		Logger()
	ctx := logger.WithContext(context.Background())

	p.pool = pool

	p.watchNewDomains(ctx)

	// If using a distributed store, watch for certificate updates from other replicas
	p.watchDistributedStore(ctx, pool)

	p.configurationChan = configurationChan

	p.certificatesMu.RLock()
	msg := p.buildMessage()
	p.certificatesMu.RUnlock()

	p.configurationChan <- msg

	renewPeriod, renewInterval := getCertificateRenewDurations(p.CertificatesDuration)
	logger.Debug().Msgf("Attempt to renew certificates %q before expiry and check every %q",
		renewPeriod, renewInterval)

	// Wait for HTTP challenge route to be ready before starting renewal
	// This prevents 404 errors when the ACME server validates challenges
	// before all replicas have registered the acme-http@internal router.
	if p.HTTPChallenge != nil {
		logger.Debug().Msg("Waiting for HTTP challenge route to be ready before starting certificate renewal")
		select {
		case <-p.httpChallengeReady:
			logger.Debug().Msg("HTTP challenge route is ready, proceeding with certificate renewal")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			logger.Warn().Msg("Timeout waiting for HTTP challenge route readiness, proceeding anyway")
		}
	}

	p.renewCertificates(ctx, renewPeriod)

	ticker := time.NewTicker(renewInterval)
	pool.GoCtx(func(ctxPool context.Context) {
		for {
			select {
			case <-ticker.C:
				p.renewCertificates(ctx, renewPeriod)
			case <-ctxPool.Done():
				ticker.Stop()
				return
			}
		}
	})

	return nil
}

func (p *Provider) getClient() (*lego.Client, error) {
	p.clientMutex.Lock()
	defer p.clientMutex.Unlock()

	logger := log.With().Str(logs.ProviderName, p.ResolverName+resolverSuffix).Logger()

	ctx := logger.WithContext(context.Background())

	if p.client != nil {
		return p.client, nil
	}

	account, err := p.initAccount(ctx)
	if err != nil {
		return nil, err
	}

	logger.Debug().Msg("Building ACME client...")

	caServer := lego.LEDirectoryProduction
	if len(p.CAServer) > 0 {
		caServer = p.CAServer
	}
	logger.Debug().Msg(caServer)

	config := lego.NewConfig(account)
	config.CADirURL = caServer
	config.Certificate.KeyType = GetKeyType(ctx, p.KeyType)
	config.UserAgent = fmt.Sprintf("containous-traefik/%s", version.Version)
	config.Certificate.DisableCommonName = p.DisableCommonName

	config.HTTPClient, err = p.createHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client: %w", err)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	// New users will need to register; be sure to save it
	if account.GetRegistration() == nil {
		reg, errR := p.register(ctx, client)
		if errR != nil {
			return nil, errR
		}

		account.Registration = reg
	}

	// Save the account once before all the certificates generation/storing
	// No certificate can be generated if account is not initialized
	err = p.Store.SaveAccount(p.ResolverName, account)
	if err != nil {
		return nil, err
	}

	if (p.DNSChallenge == nil || len(p.DNSChallenge.Provider) == 0) &&
		(p.HTTPChallenge == nil || len(p.HTTPChallenge.EntryPoint) == 0) &&
		p.TLSChallenge == nil {
		return nil, errors.New("ACME challenge not specified, please select TLS or HTTP or DNS Challenge")
	}

	if p.DNSChallenge != nil && len(p.DNSChallenge.Provider) > 0 {
		logger.Debug().Msgf("Using DNS Challenge provider: %s", p.DNSChallenge.Provider)

		var provider challenge.Provider
		provider, err = dns.NewDNSChallengeProviderByName(p.DNSChallenge.Provider)
		if err != nil {
			return nil, err
		}

		var opts []dns01.ChallengeOption

		if len(p.DNSChallenge.Resolvers) > 0 {
			opts = append(opts, dns01.AddRecursiveNameservers(p.DNSChallenge.Resolvers))
		}

		if p.DNSChallenge.Propagation != nil {
			if p.DNSChallenge.Propagation.RequireAllRNS {
				opts = append(opts, dns01.RecursiveNSsPropagationRequirement())
			}

			if p.DNSChallenge.Propagation.DisableANSChecks {
				opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
			}

			opts = append(opts, dns01.PropagationWait(time.Duration(p.DNSChallenge.Propagation.DelayBeforeChecks), p.DNSChallenge.Propagation.DisableChecks))
		}

		err = client.Challenge.SetDNS01Provider(provider, opts...)
		if err != nil {
			return nil, err
		}
	}

	if p.HTTPChallenge != nil && len(p.HTTPChallenge.EntryPoint) > 0 {
		logger.Debug().Msg("Using HTTP Challenge provider.")

		err = client.Challenge.SetHTTP01Provider(p.HTTPChallengeProvider, http01.SetDelay(time.Duration(p.HTTPChallenge.Delay)))
		if err != nil {
			return nil, err
		}
	}

	if p.TLSChallenge != nil {
		logger.Debug().Msg("Using TLS Challenge provider.")

		err = client.Challenge.SetTLSALPN01Provider(p.TLSChallengeProvider, tlsalpn01.SetDelay(time.Duration(p.TLSChallenge.Delay)))
		if err != nil {
			return nil, err
		}
	}

	p.client = client
	return p.client, nil
}

func (p *Provider) createHTTPClient() (*http.Client, error) {
	tlsConfig, err := p.createClientTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("creating client TLS config: %w", err)
	}

	return &http.Client{
		Timeout: time.Duration(p.ClientTimeout),
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: time.Duration(p.ClientResponseHeaderTimeout),
			TLSClientConfig:       tlsConfig,
		},
	}, nil
}

func (p *Provider) createClientTLSConfig() (*tls.Config, error) {
	if len(p.CACertificates) > 0 || p.CAServerName != "" {
		certPool, err := lego.CreateCertPool(p.CACertificates, p.CASystemCertPool)
		if err != nil {
			return nil, fmt.Errorf("creating cert pool with custom certificates: %w", err)
		}

		return &tls.Config{
			ServerName: p.CAServerName,
			RootCAs:    certPool,
		}, nil
	}

	// Compatibility layer with the lego.
	// https://github.com/go-acme/lego/blob/834a9089f143e3407b3f5c8b93a0e285ba231fe2/lego/client_config.go#L24-L34
	// https://github.com/go-acme/lego/blob/834a9089f143e3407b3f5c8b93a0e285ba231fe2/lego/client_config.go#L97-L113

	serverName := os.Getenv("LEGO_CA_SERVER_NAME")
	customCACertsPath := os.Getenv("LEGO_CA_CERTIFICATES")

	if customCACertsPath == "" && serverName == "" {
		return nil, nil
	}

	useSystemCertPool, _ := strconv.ParseBool(os.Getenv("LEGO_CA_SYSTEM_CERT_POOL"))

	certPool, err := lego.CreateCertPool(strings.Split(customCACertsPath, string(os.PathListSeparator)), useSystemCertPool)
	if err != nil {
		return nil, fmt.Errorf("creating cert pool: %w", err)
	}

	return &tls.Config{
		ServerName: serverName,
		RootCAs:    certPool,
	}, nil
}

func (p *Provider) initAccount(ctx context.Context) (*Account, error) {
	if p.account == nil || len(p.account.Email) == 0 {
		var err error
		p.account, err = NewAccount(ctx, p.Email, p.KeyType)
		if err != nil {
			return nil, err
		}
	}

	// Set the KeyType if not already defined in the account
	if len(p.account.KeyType) == 0 {
		p.account.KeyType = GetKeyType(ctx, p.KeyType)
	}

	return p.account, nil
}

func (p *Provider) register(ctx context.Context, client *lego.Client) (*registration.Resource, error) {
	logger := log.Ctx(ctx)

	if p.EAB != nil {
		logger.Info().Msg("Register with external account binding...")

		eabOptions := registration.RegisterEABOptions{TermsOfServiceAgreed: true, Kid: p.EAB.Kid, HmacEncoded: p.EAB.HmacEncoded}

		return client.Registration.RegisterWithExternalAccountBinding(eabOptions)
	}

	logger.Info().Msg("Register...")

	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}

func (p *Provider) resolveDomains(ctx context.Context, domains []string, tlsStore string) {
	logger := log.Ctx(ctx)

	if len(domains) == 0 {
		logger.Debug().Msg("No domain parsed in provider ACME")
		return
	}

	logger.Debug().Msgf("Trying to challenge certificate for domain %v found in HostSNI rule", domains)

	var domain types.Domain
	if len(domains) > 0 {
		domain = types.Domain{Main: domains[0]}
		if len(domains) > 1 {
			domain.SANs = domains[1:]
		}

		safe.Go(func() {
			dom, cert, err := p.resolveCertificate(ctx, domain, tlsStore)
			if err != nil {
				logger.Error().Err(err).Strs("domains", domains).Msg("Unable to obtain ACME certificate for domains")
				return
			}

			err = p.addCertificateForDomain(dom, cert, tlsStore)
			if err != nil {
				logger.Error().Err(err).Strs("domains", dom.ToStrArray()).Msg("Error adding certificate for domains")
			}
		})
	}
}

func (p *Provider) watchNewDomains(ctx context.Context) {
	rootLogger := log.Ctx(ctx).With().Str(logs.ProviderName, p.ResolverName+resolverSuffix).Str("ACME CA", p.Configuration.CAServer).Logger()
	ctx = rootLogger.WithContext(ctx)

	p.pool.GoCtx(func(ctxPool context.Context) {
		for {
			select {
			case config := <-p.configFromListenerChan:
				if config.TCP != nil {
					for routerName, route := range config.TCP.Routers {
						if route.TLS == nil || route.TLS.CertResolver != p.ResolverName {
							continue
						}

						logger := rootLogger.With().Str(logs.RouterName, routerName).Str(logs.Rule, route.Rule).Logger()
						ctxRouter := logger.WithContext(ctx)

						if len(route.TLS.Domains) > 0 {
							domains := deleteUnnecessaryDomains(ctxRouter, route.TLS.Domains)
							for _, domain := range domains {
								safe.Go(func() {
									dom, cert, err := p.resolveCertificate(ctx, domain, traefiktls.DefaultTLSStoreName)
									if err != nil {
										logger.Error().Err(err).Strs("domains", domain.ToStrArray()).Msg("Unable to obtain ACME certificate for domains")
										return
									}

									err = p.addCertificateForDomain(dom, cert, traefiktls.DefaultTLSStoreName)
									if err != nil {
										logger.Error().Err(err).Strs("domains", dom.ToStrArray()).Msg("Error adding certificate for domains")
									}
								})
							}
						} else {
							domains, err := tcpmuxer.ParseHostSNI(route.Rule)
							if err != nil {
								logger.Error().Err(err).Msg("Error parsing domains in provider ACME")
								continue
							}
							p.resolveDomains(ctxRouter, domains, traefiktls.DefaultTLSStoreName)
						}
					}
				}

				if config.HTTP != nil {
					for routerName, route := range config.HTTP.Routers {
						if route.TLS == nil || route.TLS.CertResolver != p.ResolverName {
							continue
						}

						logger := rootLogger.With().Str(logs.RouterName, routerName).Str(logs.Rule, route.Rule).Logger()
						ctxRouter := logger.WithContext(ctx)

						if len(route.TLS.Domains) > 0 {
							domains := deleteUnnecessaryDomains(ctxRouter, route.TLS.Domains)
							for _, domain := range domains {
								safe.Go(func() {
									dom, cert, err := p.resolveCertificate(ctx, domain, traefiktls.DefaultTLSStoreName)
									if err != nil {
										logger.Error().Err(err).Strs("domains", domain.ToStrArray()).Msg("Unable to obtain ACME certificate for domains")
										return
									}

									err = p.addCertificateForDomain(dom, cert, traefiktls.DefaultTLSStoreName)
									if err != nil {
										logger.Error().Err(err).Strs("domains", dom.ToStrArray()).Msg("Error adding certificate for domain")
									}
								})
							}
						} else {
							domains, err := httpmuxer.ParseDomains(route.Rule)
							if err != nil {
								logger.Error().Err(err).Msg("Error parsing domains in provider ACME")
								continue
							}
							p.resolveDomains(ctxRouter, domains, traefiktls.DefaultTLSStoreName)
						}
					}
				}

				if config.TLS == nil {
					continue
				}

				for tlsStoreName, tlsStore := range config.TLS.Stores {
					logger := rootLogger.With().Str(logs.TLSStoreName, tlsStoreName).Logger()

					if tlsStore.DefaultCertificate != nil && tlsStore.DefaultGeneratedCert != nil {
						logger.Warn().Msg("defaultCertificate and defaultGeneratedCert cannot be defined at the same time.")
					}

					// Gives precedence to the user defined default certificate.
					if tlsStore.DefaultCertificate != nil || tlsStore.DefaultGeneratedCert == nil {
						continue
					}

					if tlsStore.DefaultGeneratedCert.Domain == nil || tlsStore.DefaultGeneratedCert.Resolver == "" {
						logger.Warn().Msg("default generated certificate domain or resolver is missing.")
						continue
					}

					if tlsStore.DefaultGeneratedCert.Resolver != p.ResolverName {
						continue
					}

					validDomains, err := p.sanitizeDomains(ctx, *tlsStore.DefaultGeneratedCert.Domain)
					if err != nil {
						logger.Error().Err(err).Strs("domains", tlsStore.DefaultGeneratedCert.Domain.ToStrArray()).Msg("domains validation")
					}

					if p.certExists(validDomains) {
						logger.Debug().Msg("Default ACME certificate generation is not required.")
						continue
					}

					safe.Go(func() {
						cert, err := p.resolveDefaultCertificate(ctx, validDomains)
						if err != nil {
							logger.Error().Err(err).Strs("domains", validDomains).Msgf("Unable to obtain ACME certificate for domain")
							return
						}

						domain := types.Domain{
							Main: validDomains[0],
						}
						if len(validDomains) > 0 {
							domain.SANs = validDomains[1:]
						}

						err = p.addCertificateForDomain(domain, cert, traefiktls.DefaultTLSStoreName)
						if err != nil {
							logger.Error().Err(err).Msg("Error adding certificate for domain")
						}
					})
				}
			case <-ctxPool.Done():
				return
			}
		}
	})
}

func (p *Provider) resolveDefaultCertificate(ctx context.Context, domains []string) (*certificate.Resource, error) {
	logger := log.Ctx(ctx)

	p.resolvingDomainsMutex.Lock()

	sortedDomains := slices.Clone(domains)
	slices.Sort(sortedDomains)

	domainKey := strings.Join(sortedDomains, ",")

	if _, ok := p.resolvingDomains[domainKey]; ok {
		p.resolvingDomainsMutex.Unlock()
		return nil, nil
	}

	p.resolvingDomains[domainKey] = struct{}{}

	for _, certDomain := range domains {
		p.resolvingDomains[certDomain] = struct{}{}
	}

	p.resolvingDomainsMutex.Unlock()

	defer p.removeResolvingDomains(append(domains, domainKey))

	logger.Debug().Msgf("Loading ACME certificates %+v...", domains)

	client, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("cannot get ACME client %w", err)
	}

	request := certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		EmailAddresses: p.EmailAddresses,
		Profile:        p.Profile,
		PreferredChain: p.PreferredChain,
	}

	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("unable to generate a certificate for the domains %v: %w", domains, err)
	}
	if cert == nil {
		return nil, fmt.Errorf("unable to generate a certificate for the domains %v", domains)
	}
	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
		return nil, fmt.Errorf("certificate for domains %v is empty: %v", domains, cert)
	}

	logger.Debug().Msgf("Default certificate obtained for domains %+v", domains)

	return cert, nil
}

// watchDistributedStore watches the distributed store for certificate updates from other replicas.
// When another replica obtains a certificate, this replica will be notified and refresh its local cache.
func (p *Provider) watchDistributedStore(ctx context.Context, pool *safe.Pool) {
	ds, ok := p.Store.(DistributedStore)
	if !ok {
		return
	}

	logger := *log.Ctx(ctx)

	pool.GoCtx(func(ctxPool context.Context) {
		retryInterval := 5 * time.Second
		maxRetryInterval := 5 * time.Minute

		for {
			updates, err := ds.Watch(ctxPool, p.ResolverName)
			if err != nil {
				logger.Warn().Err(err).Dur("retryIn", retryInterval).
					Msg("Failed to watch distributed store for certificate updates, will retry")
				select {
				case <-ctxPool.Done():
					return
				case <-time.After(retryInterval):
				}
				retryInterval = min(retryInterval*2, maxRetryInterval)
				continue
			}
			// Reset backoff on successful watch
			retryInterval = 5 * time.Second
			logger.Info().Msg("Distributed store watch established")

			p.consumeDistributedUpdates(ctxPool, updates, logger)

			// If consumeDistributedUpdates returned, the watch channel was closed.
			// Retry the watch unless the context is done.
			select {
			case <-ctxPool.Done():
				return
			default:
				logger.Warn().Msg("Distributed store watch channel closed, reconnecting")
			}
		}
	})
}

// consumeDistributedUpdates processes certificate update notifications from the distributed store watch channel.
func (p *Provider) consumeDistributedUpdates(ctx context.Context, updates <-chan struct{}, logger zerolog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-updates:
			if !ok {
				return
			}

			// Refresh certificates from the distributed store
			freshCerts, err := p.Store.GetCertificates(p.ResolverName)
			if err != nil {
				logger.Warn().Err(err).Msg("Failed to refresh certificates from distributed store")
				continue
			}

			p.certificatesMu.Lock()
			p.certificates = freshCerts
			p.certificatesMu.Unlock()

			// Notify configuration channel with updated certificates
			p.configurationChan <- p.buildMessage()
			logger.Debug().Msg("Refreshed certificates from distributed store")

			// Re-send the last dynamic configuration to trigger
			// resolveNewCertificates for any domains that were waiting
			// for the KV backend to come online. This bypasses the
			// server's config deduplication.
			p.lastConfigMu.RLock()
			cfg := p.lastConfig
			p.lastConfigMu.RUnlock()

			if cfg != nil {
				select {
				case p.configFromListenerChan <- *cfg:
					logger.Debug().Msg("Re-triggered domain resolution after distributed store update")
				default:
				}
			}
		}
	}
}

func (p *Provider) resolveCertificate(ctx context.Context, domain types.Domain, tlsStore string) (types.Domain, *certificate.Resource, error) {
	domains, err := p.sanitizeDomains(ctx, domain)
	if err != nil {
		return types.Domain{}, nil, err
	}

	// Check if provided certificates are not already in progress and lock them if needed
	uncheckedDomains := p.getUncheckedDomains(ctx, domains, tlsStore)
	if len(uncheckedDomains) == 0 {
		return types.Domain{}, nil, nil
	}

	logger := log.Ctx(ctx)

	// If using distributed store, acquire distributed lock (blocking).
	// This ensures only one replica obtains a certificate for a given domain.
	// Other replicas will wait for the lock, then check if cert was already obtained.
	var distStore DistributedStore
	var domainKey string
	if ds, ok := p.Store.(DistributedStore); ok {
		distStore = ds
		domainKey = strings.Join(uncheckedDomains, ",")
		logger.Debug().Str("domainKey", domainKey).Msg("Acquiring distributed lock")

		// Acquire lock - blocks until we get it, context is canceled, or timeout expires.
		// The 60s timeout bounds how long we wait if another replica holds the lock.
		// Note: The lock itself uses TTL-based auto-expiration (configured in KVStore),
		// so even if a replica crashes while holding the lock, it will auto-release.
		lockCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		_, err := distStore.AcquireLock(lockCtx, p.ResolverName, domainKey)
		if err != nil {
			cancel()
			// Lock acquisition failed - don't proceed with certificate request.
			// This prevents thundering herd: other replicas should wait or use cached certs.
			logger.Warn().Err(err).Msgf("Failed to acquire distributed lock for %v, skipping certificate request", uncheckedDomains)
			p.removeResolvingDomains(uncheckedDomains)
			return types.Domain{}, nil, nil
		}

		logger.Debug().Str("domainKey", domainKey).Msg("Acquired distributed lock")

		// cancel() must be deferred AFTER ReleaseLock to keep the lock context alive
		// during certificate operations. Canceling early destroys the lock session.
		defer cancel()
		defer func() {
			if err := distStore.ReleaseLock(p.ResolverName, domainKey); err != nil {
				logger.Warn().Err(err).Msg("Failed to release distributed lock")
			}
		}()

		// After acquiring lock, check if certificate was already obtained by another replica.
		// This is the critical check - if we waited for a lock and another replica got the cert,
		// we should use that cert instead of requesting a new one.
		// Use GetCertificatesFresh to bypass local cache and get fresh data from KV store.
		// CRITICAL: If we cannot verify fresh certs, we MUST NOT proceed to generate a new certificate
		// as another replica may have already generated one. This prevents thundering herd.
		freshCerts, err := distStore.GetCertificatesFresh(p.ResolverName)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get fresh certificates from distributed store, aborting to prevent duplicate certificate generation")
			p.removeResolvingDomains(uncheckedDomains)
			return types.Domain{}, nil, fmt.Errorf("cannot verify certificates from distributed store: %w", err)
		}

		logger.Debug().Msgf("Got %d fresh certs from distributed store", len(freshCerts))
		for _, cert := range freshCerts {
			certDomains := cert.Domain.ToStrArray()
			logger.Debug().Msgf("Fresh cert has domains: %v", certDomains)
			for _, d := range uncheckedDomains {
				if slices.Contains(certDomains, d) {
					logger.Info().Msgf("Certificate for %s already exists in store, using it", d)
					p.removeResolvingDomains(uncheckedDomains)
					// Refresh local certificates
					p.certificatesMu.Lock()
					p.certificates = freshCerts
					p.certificatesMu.Unlock()
					p.configurationChan <- p.buildMessage()
					return types.Domain{}, nil, nil
				}
			}
		}
		logger.Debug().Msgf("No matching cert found in %d fresh certs for domains %v", len(freshCerts), uncheckedDomains)
	}

	defer p.removeResolvingDomains(uncheckedDomains)

	logger.Debug().Msgf("Loading ACME certificates %+v...", uncheckedDomains)

	client, err := p.getClient()
	if err != nil {
		return types.Domain{}, nil, fmt.Errorf("cannot get ACME client %w", err)
	}

	request := certificate.ObtainRequest{
		Domains:        domains,
		Bundle:         true,
		EmailAddresses: p.EmailAddresses,
		Profile:        p.Profile,
		PreferredChain: p.PreferredChain,
	}

	cert, err := client.Certificate.Obtain(request)
	if err != nil {
		return types.Domain{}, nil, fmt.Errorf("unable to generate a certificate for the domains %v: %w", uncheckedDomains, err)
	}
	if cert == nil {
		return types.Domain{}, nil, fmt.Errorf("unable to generate a certificate for the domains %v", uncheckedDomains)
	}
	if len(cert.Certificate) == 0 || len(cert.PrivateKey) == 0 {
		return types.Domain{}, nil, fmt.Errorf("certificate for domains %v is empty: %v", uncheckedDomains, cert)
	}

	logger.Debug().Msgf("Certificates obtained for domains %+v", uncheckedDomains)

	domain = types.Domain{Main: uncheckedDomains[0]}
	if len(uncheckedDomains) > 1 {
		domain.SANs = uncheckedDomains[1:]
	}

	// If using distributed store, save certificate NOW (before releasing lock).
	// This ensures other replicas waiting for the lock will find the certificate when they check.
	if distStore != nil {
		certObj := Certificate{Certificate: cert.Certificate, Key: cert.PrivateKey, Domain: domain}
		p.certificatesMu.Lock()
		p.certificates = append(p.certificates, &CertAndStore{Certificate: certObj, Store: tlsStore})
		if err := p.Store.SaveCertificates(p.ResolverName, p.certificates); err != nil {
			logger.Warn().Err(err).Msg("Failed to save certificate to distributed store")
		}
		p.certificatesMu.Unlock()
	}

	return domain, cert, nil
}

func (p *Provider) removeResolvingDomains(resolvingDomains []string) {
	p.resolvingDomainsMutex.Lock()
	defer p.resolvingDomainsMutex.Unlock()

	for _, domain := range resolvingDomains {
		delete(p.resolvingDomains, domain)
	}
}

func (p *Provider) addCertificateForDomain(domain types.Domain, crt *certificate.Resource, tlsStore string) error {
	if crt == nil {
		return nil
	}

	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()

	cert := Certificate{Certificate: crt.Certificate, Key: crt.PrivateKey, Domain: domain}

	certUpdated := false
	for _, domainsCertificate := range p.certificates {
		if reflect.DeepEqual(domain, domainsCertificate.Certificate.Domain) {
			domainsCertificate.Certificate = cert
			certUpdated = true
			break
		}
	}

	if !certUpdated {
		p.certificates = append(p.certificates, &CertAndStore{Certificate: cert, Store: tlsStore})
	}

	p.configurationChan <- p.buildMessage()

	return p.Store.SaveCertificates(p.ResolverName, p.certificates)
}

// getCertificateRenewDurations returns renew durations calculated from the given certificatesDuration in hours.
// The first (RenewPeriod) is the period before the end of the certificate duration, during which the certificate should be renewed.
// The second (RenewInterval) is the interval between renew attempts.
func getCertificateRenewDurations(certificatesDuration int) (time.Duration, time.Duration) {
	switch {
	case certificatesDuration >= 365*24: // >= 1 year
		return 4 * 30 * 24 * time.Hour, 7 * 24 * time.Hour // 4 month, 1 week
	case certificatesDuration >= 3*30*24: // >= 90 days
		return 30 * 24 * time.Hour, 24 * time.Hour // 30 days, 1 day
	case certificatesDuration >= 30*24: // >= 30 days
		return 10 * 24 * time.Hour, 12 * time.Hour // 10 days, 12 hours
	case certificatesDuration >= 7*24: // >= 7 days
		return 24 * time.Hour, time.Hour // 1 days, 1 hour
	case certificatesDuration >= 24: // >= 1 days
		return 6 * time.Hour, 10 * time.Minute // 6 hours, 10 minutes
	default:
		return 20 * time.Minute, time.Minute
	}
}

// deleteUnnecessaryDomains deletes from the configuration :
// - Duplicated domains
// - Domains which are checked by wildcard domain.
func deleteUnnecessaryDomains(ctx context.Context, domains []types.Domain) []types.Domain {
	var newDomains []types.Domain

	logger := log.Ctx(ctx)

	for idxDomainToCheck, domainToCheck := range domains {
		keepDomain := true

		for idxDomain, domain := range domains {
			if idxDomainToCheck == idxDomain {
				continue
			}

			if reflect.DeepEqual(domain, domainToCheck) {
				if idxDomainToCheck > idxDomain {
					logger.Warn().Msgf("The domain %v is duplicated in the configuration but will be process by ACME provider only once.", domainToCheck)
					keepDomain = false
				}
				break
			}

			// Check if CN or SANS to check already exists
			// or cannot be checked by a wildcard
			var newDomainsToCheck []string
			for _, domainProcessed := range domainToCheck.ToStrArray() {
				if idxDomain < idxDomainToCheck && isDomainAlreadyChecked(domainProcessed, domain.ToStrArray()) {
					// The domain is duplicated in a CN
					logger.Warn().Msgf("Domain %q is duplicated in the configuration or validated by the domain %v. It will be processed once.", domainProcessed, domain)
					continue
				} else if domain.Main != domainProcessed && strings.HasPrefix(domain.Main, "*") && isDomainAlreadyChecked(domainProcessed, []string{domain.Main}) {
					// Check if a wildcard can validate the domain
					logger.Warn().Msgf("Domain %q will not be processed by ACME provider because it is validated by the wildcard %q", domainProcessed, domain.Main)
					continue
				}
				newDomainsToCheck = append(newDomainsToCheck, domainProcessed)
			}

			// Delete the domain if both Main and SANs can be validated by the wildcard domain
			// otherwise keep the unchecked values
			if newDomainsToCheck == nil {
				keepDomain = false
				break
			}
			domainToCheck.Set(newDomainsToCheck)
		}

		if keepDomain {
			newDomains = append(newDomains, domainToCheck)
		}
	}

	return newDomains
}

func (p *Provider) buildMessage() dynamic.Message {
	conf := dynamic.Message{
		ProviderName: p.ResolverName + ".acme",
		Configuration: &dynamic.Configuration{
			HTTP: &dynamic.HTTPConfiguration{
				Routers:     map[string]*dynamic.Router{},
				Middlewares: map[string]*dynamic.Middleware{},
				Services:    map[string]*dynamic.Service{},
			},
			TLS: &dynamic.TLSConfiguration{},
		},
	}

	for _, cert := range p.certificates {
		certConf := &traefiktls.CertAndStores{
			Certificate: traefiktls.Certificate{
				CertFile: types.FileOrContent(cert.Certificate.Certificate),
				KeyFile:  types.FileOrContent(cert.Key),
			},
			Stores: []string{cert.Store},
		}
		conf.Configuration.TLS.Certificates = append(conf.Configuration.TLS.Certificates, certConf)
	}

	return conf
}

// refreshCertificatesFromStore refreshes certificates from the distributed store for the given domain.
// It updates the local certificate cache with fresh data from the KV store if a matching certificate is found.
// Returns nil if the certificate was successfully refreshed, or an error otherwise.
func (p *Provider) refreshCertificatesFromStore(ctx context.Context, domain types.Domain) error {
	logger := log.Ctx(ctx)

	distStore, ok := p.Store.(DistributedStore)
	if !ok {
		return errors.New("store is not a distributed store")
	}

	freshCerts, err := distStore.GetCertificatesFresh(p.ResolverName)
	if err != nil {
		return fmt.Errorf("failed to get fresh certificates from store: %w", err)
	}

	domainsToFind := domain.ToStrArray()
	for _, cert := range freshCerts {
		certDomains := cert.Domain.ToStrArray()
		for _, d := range domainsToFind {
			if slices.Contains(certDomains, d) {
				// Found the certificate in the store, update local cache.
				logger.Info().Msgf("Refreshed certificate for %q from distributed store", d)
				p.certificatesMu.Lock()
				p.certificates = freshCerts
				p.certificatesMu.Unlock()
				p.configurationChan <- p.buildMessage()
				return nil
			}
		}
	}

	return errors.New("certificate not found in store")
}

// isCertificateRenewedByAnotherInstance checks if a certificate for the given domain
// has been renewed by another instance by comparing with fresh data from the distributed store.
// It compares the NotAfter times - if the fresh certificate has a later expiry than the
// original, another instance has already renewed it.
// Returns:
//   - renewed: true if the certificate was renewed by another instance
//   - freshCerts: the fresh certificates list (nil if fetch failed)
//   - err: error if we could not verify from distributed store (caller should NOT proceed with renewal).
func (p *Provider) isCertificateRenewedByAnotherInstance(ctx context.Context, originalCert *CertAndStore) (renewed bool, freshCerts []*CertAndStore, err error) {
	distStore, ok := p.Store.(DistributedStore)
	if !ok {
		return false, nil, nil
	}

	origX509, origErr := getX509Certificate(ctx, &originalCert.Certificate)
	if origErr != nil || origX509 == nil {
		return false, nil, fmt.Errorf("cannot parse original certificate for renewal check: %w", origErr)
	}

	freshCerts, freshErr := distStore.GetCertificatesFresh(p.ResolverName)
	if freshErr != nil {
		return false, nil, fmt.Errorf("cannot verify certificates from distributed store: %w", freshErr)
	}

	for _, freshCert := range freshCerts {
		if freshCert.Domain.Main == originalCert.Domain.Main {
			freshX509, parseErr := getX509Certificate(ctx, &freshCert.Certificate)
			if parseErr == nil && freshX509 != nil && freshX509.NotAfter.After(origX509.NotAfter) {
				// Certificate has been renewed by another instance (fresher NotAfter time)
				return true, freshCerts, nil
			}
			break
		}
	}

	return false, nil, nil
}

func (p *Provider) renewCertificates(ctx context.Context, renewPeriod time.Duration) {
	logger := log.Ctx(ctx)

	logger.Info().Msg("Testing certificate renew...")

	p.certificatesMu.RLock()

	var certificates []*CertAndStore
	for _, cert := range p.certificates {
		crt, err := getX509Certificate(ctx, &cert.Certificate)
		// If there's an error, we assume the cert is broken, and needs update
		if err != nil || crt == nil || crt.NotAfter.Before(time.Now().Add(renewPeriod)) {
			certificates = append(certificates, cert)
		}
	}

	p.certificatesMu.RUnlock()

	for _, cert := range certificates {
		p.renewSingleCertificate(ctx, cert, renewPeriod)
	}
}

// renewSingleCertificate renews a single certificate, handling distributed locking if needed.
func (p *Provider) renewSingleCertificate(ctx context.Context, cert *CertAndStore, renewPeriod time.Duration) {
	logger := log.Ctx(ctx)

	// Get the domain key for locking (same approach as initial certificate acquisition).
	domainKey := cert.Domain.Main
	if after, ok := strings.CutPrefix(domainKey, "*"); ok {
		domainKey = after
	}

	// Check if we should use distributed locking for renewal.
	// This prevents multiple replicas from renewing the same certificate simultaneously.
	distStore, ok := p.Store.(DistributedStore)
	if ok {
		lockCtx, lockCancel := context.WithTimeout(ctx, 60*time.Second)
		_, err := distStore.AcquireLock(lockCtx, p.ResolverName, domainKey)
		lockCancel()
		if err != nil {
			logger.Debug().Err(err).Msgf("Could not acquire lock for renewal %q, another instance may be renewing", domainKey)

			// Check if certificate was renewed by another instance by refreshing from store.
			if refreshErr := p.refreshCertificatesFromStore(ctx, cert.Domain); refreshErr == nil {
				// Certificate was successfully refreshed from store, skip renewal.
				crt, parseErr := getX509Certificate(ctx, &cert.Certificate)
				if parseErr == nil && crt != nil && !crt.NotAfter.Before(time.Now().Add(renewPeriod)) {
					logger.Info().Msgf("Certificate %q was renewed by another instance", domainKey)
					return
				}
			}

			// Could not acquire lock and could not refresh - skip this renewal attempt.
			// We'll retry on the next renewal interval.
			logger.Warn().Err(err).Msgf("Failed to acquire renewal lock for %q, will retry later", domainKey)
			return
		}
		logger.Debug().Str("domainKey", domainKey).Msg("Acquired distributed lock for renewal")
		// Release lock when this function returns.
		defer func() {
			if releaseErr := distStore.ReleaseLock(p.ResolverName, domainKey); releaseErr != nil {
				logger.Warn().Err(releaseErr).Msgf("Failed to release renewal lock for %q", domainKey)
			} else {
				logger.Debug().Str("domainKey", domainKey).Msg("Released distributed lock for renewal")
			}
		}()

		// After acquiring the lock, re-check if renewal is still needed.
		// Another replica may have already renewed the certificate while we were waiting.
		// CRITICAL: If we cannot verify from the distributed store, we must NOT proceed
		// with renewal to prevent duplicate certificate generation.
		renewed, freshCerts, verifyErr := p.isCertificateRenewedByAnotherInstance(ctx, cert)
		if verifyErr != nil {
			logger.Error().Err(verifyErr).Msgf("Failed to verify certificates from distributed store for %q, aborting renewal to prevent duplicates", domainKey)
			return
		}
		if renewed {
			logger.Info().Msgf("Certificate %q was already renewed by another instance (after lock acquired)", domainKey)
			// Update local cache with fresh certificates
			p.certificatesMu.Lock()
			p.certificates = freshCerts
			p.certificatesMu.Unlock()
			p.configurationChan <- p.buildMessage()
			return
		}
	}

	client, err := p.getClient()
	if err != nil {
		logger.Info().Err(err).Msgf("Error renewing ACME certificate: %+v", cert.Domain)
		return
	}

	logger.Info().Msgf("Renewing ACME certificate: %+v", cert.Domain)

	res := certificate.Resource{
		Domain:      cert.Domain.Main,
		PrivateKey:  cert.Key,
		Certificate: cert.Certificate.Certificate,
	}

	opts := &certificate.RenewOptions{
		Bundle:         true,
		EmailAddresses: p.EmailAddresses,
		Profile:        p.Profile,
		PreferredChain: p.PreferredChain,
	}

	renewedCert, err := client.Certificate.RenewWithOptions(res, opts)
	if err != nil {
		logger.Error().Err(err).Msgf("Error renewing ACME certificate: %v", cert.Domain)
		return
	}

	if len(renewedCert.Certificate) == 0 || len(renewedCert.PrivateKey) == 0 {
		logger.Error().Msgf("domains %v renew certificate with no value: %v", cert.Domain.ToStrArray(), cert)
		return
	}

	err = p.addCertificateForDomain(cert.Domain, renewedCert, cert.Store)
	if err != nil {
		logger.Error().Err(err).Msg("Error adding certificate for domain")
	}
}

// Get provided certificate which check a domains list (Main and SANs)
// from static and dynamic provided certificates.
func (p *Provider) getUncheckedDomains(ctx context.Context, domainsToCheck []string, tlsStore string) []string {
	log.Ctx(ctx).Debug().Msgf("Looking for provided certificate(s) to validate %q...", domainsToCheck)

	var allDomains []string
	store := p.tlsManager.GetStore(tlsStore)
	if store != nil {
		storeDomains := store.GetAllDomains()
		allDomains = append(allDomains, storeDomains...)
	}

	// Get ACME certificates

	p.certificatesMu.RLock()
	for _, cert := range p.certificates {
		certDomains := strings.Join(cert.Domain.ToStrArray(), ",")
		allDomains = append(allDomains, certDomains)
	}
	p.certificatesMu.RUnlock()

	p.resolvingDomainsMutex.Lock()
	defer p.resolvingDomainsMutex.Unlock()

	// Get currently resolved domains
	for domain := range p.resolvingDomains {
		allDomains = append(allDomains, domain)
	}

	uncheckedDomains := searchUncheckedDomains(ctx, domainsToCheck, allDomains)

	// Lock domains that will be resolved by this routine
	for _, domain := range uncheckedDomains {
		p.resolvingDomains[domain] = struct{}{}
	}

	return uncheckedDomains
}

func searchUncheckedDomains(ctx context.Context, domainsToCheck, existentDomains []string) []string {
	var uncheckedDomains []string
	for _, domainToCheck := range domainsToCheck {
		if !isDomainAlreadyChecked(domainToCheck, existentDomains) {
			uncheckedDomains = append(uncheckedDomains, domainToCheck)
		}
	}

	logger := log.Ctx(ctx)
	if len(uncheckedDomains) == 0 {
		logger.Debug().Strs("domains", domainsToCheck).Msg("No ACME certificate generation required for domains")
	} else {
		logger.Debug().Strs("domains", domainsToCheck).Msgf("Domains need ACME certificates generation for domains %q.", strings.Join(uncheckedDomains, ","))
	}
	return uncheckedDomains
}

func getX509Certificate(ctx context.Context, cert *Certificate) (*x509.Certificate, error) {
	logger := log.Ctx(ctx)

	tlsCert, err := tls.X509KeyPair(cert.Certificate, cert.Key)
	if err != nil {
		logger.Error().Err(err).
			Str("domain", cert.Domain.Main).
			Strs("SANs", cert.Domain.SANs).
			Msg("Failed to load TLS key pair from ACME certificate for domain, certificate will be renewed")
		return nil, err
	}

	crt := tlsCert.Leaf
	if crt == nil {
		crt, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			logger.Error().Err(err).
				Str("domain", cert.Domain.Main).
				Strs("SANs", cert.Domain.SANs).
				Msg("Failed to parse TLS key pair from ACME certificate for domain, certificate will be renewed")
		}
	}

	return crt, err
}

// sanitizeDomains checks if given domain is allowed to generate a ACME certificate and return it.
func (p *Provider) sanitizeDomains(ctx context.Context, domain types.Domain) ([]string, error) {
	domains := domain.ToStrArray()
	if len(domains) == 0 {
		return nil, errors.New("no domain was given")
	}

	var cleanDomains []string
	for _, dom := range domains {
		if strings.HasPrefix(dom, "*.*") {
			return nil, fmt.Errorf("unable to generate a wildcard certificate in ACME provider for domain %q : ACME does not allow '*.*' wildcard domain", strings.Join(domains, ","))
		}

		canonicalDomain := types.CanonicalDomain(dom)
		cleanDomain := dns01.UnFqdn(canonicalDomain)
		if canonicalDomain != cleanDomain {
			log.Ctx(ctx).Warn().Msgf("FQDN detected, please remove the trailing dot: %s", canonicalDomain)
		}

		cleanDomains = append(cleanDomains, cleanDomain)
	}

	return cleanDomains, nil
}

// certExists returns whether a certificate already exists for given domains.
func (p *Provider) certExists(validDomains []string) bool {
	p.certificatesMu.RLock()
	defer p.certificatesMu.RUnlock()

	sortedDomains := make([]string, len(validDomains))
	copy(sortedDomains, validDomains)
	sort.Strings(sortedDomains)

	for _, cert := range p.certificates {
		domains := cert.Certificate.Domain.ToStrArray()
		sort.Strings(domains)
		if reflect.DeepEqual(domains, sortedDomains) {
			return true
		}
	}

	return false
}

func isDomainAlreadyChecked(domainToCheck string, existentDomains []string) bool {
	for _, certDomains := range existentDomains {
		for _, certDomain := range strings.Split(certDomains, ",") {
			if types.MatchDomain(domainToCheck, certDomain) {
				return true
			}
		}
	}
	return false
}
