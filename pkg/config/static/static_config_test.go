package static

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/traefik/traefik/v3/pkg/provider/acme"
)

func pointer[T any](v T) *T { return &v }

func TestHasEntrypoint(t *testing.T) {
	tests := []struct {
		desc        string
		entryPoints map[string]*EntryPoint
		assert      assert.BoolAssertionFunc
	}{
		{
			desc:   "no user defined entryPoints",
			assert: assert.False,
		},
		{
			desc: "user defined entryPoints",
			entryPoints: map[string]*EntryPoint{
				"foo": {},
			},
			assert: assert.True,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			cfg := &Configuration{
				EntryPoints: test.entryPoints,
			}

			test.assert(t, cfg.hasUserDefinedEntrypoint())
		})
	}
}

func TestConfiguration_SetEffectiveConfiguration(t *testing.T) {
	testCases := []struct {
		desc     string
		conf     *Configuration
		expected *Configuration
	}{
		{
			desc: "empty",
			conf: &Configuration{
				Providers: &Providers{},
			},
			expected: &Configuration{
				EntryPoints: EntryPoints{"http": &EntryPoint{
					Address:         ":80",
					AllowACMEByPass: false,
					ReusePort:       false,
					AsDefault:       false,
					Transport: &EntryPointsTransport{
						LifeCycle: &LifeCycle{
							GraceTimeOut: 10000000000,
						},
						RespondingTimeouts: &RespondingTimeouts{
							ReadTimeout: 60000000000,
							IdleTimeout: 180000000000,
						},
					},
					ProxyProtocol:    nil,
					ForwardedHeaders: &ForwardedHeaders{},
					HTTP: HTTPConfig{
						SanitizePath:   pointer(true),
						MaxHeaderBytes: 1048576,
					},
					HTTP2: &HTTP2Config{
						MaxConcurrentStreams:      250,
						MaxDecoderHeaderTableSize: 4096,
						MaxEncoderHeaderTableSize: 4096,
					},
					HTTP3: nil,
					UDP: &UDPConfig{
						Timeout: 3000000000,
					},
				}},
				Providers: &Providers{},
			},
		},
		{
			desc: "ACME simple",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"foo": {
						ACME: &acme.Configuration{
							DNSChallenge: &acme.DNSChallenge{
								Provider: "bar",
							},
						},
					},
				},
			},
			expected: &Configuration{
				EntryPoints: EntryPoints{"http": &EntryPoint{
					Address:         ":80",
					AllowACMEByPass: false,
					ReusePort:       false,
					AsDefault:       false,
					Transport: &EntryPointsTransport{
						LifeCycle: &LifeCycle{
							GraceTimeOut: 10000000000,
						},
						RespondingTimeouts: &RespondingTimeouts{
							ReadTimeout: 60000000000,
							IdleTimeout: 180000000000,
						},
					},
					ProxyProtocol:    nil,
					ForwardedHeaders: &ForwardedHeaders{},
					HTTP: HTTPConfig{
						SanitizePath:   pointer(true),
						MaxHeaderBytes: 1048576,
					},
					HTTP2: &HTTP2Config{
						MaxConcurrentStreams:      250,
						MaxDecoderHeaderTableSize: 4096,
						MaxEncoderHeaderTableSize: 4096,
					},
					HTTP3: nil,
					UDP: &UDPConfig{
						Timeout: 3000000000,
					},
				}},
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"foo": {
						ACME: &acme.Configuration{
							CAServer: "https://acme-v02.api.letsencrypt.org/directory",
							DNSChallenge: &acme.DNSChallenge{
								Provider: "bar",
							},
						},
					},
				},
			},
		},
		{
			desc: "ACME deprecation DelayBeforeCheck",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"foo": {
						ACME: &acme.Configuration{
							DNSChallenge: &acme.DNSChallenge{
								Provider:         "bar",
								DelayBeforeCheck: 123,
							},
						},
					},
				},
			},
			expected: &Configuration{
				EntryPoints: EntryPoints{"http": &EntryPoint{
					Address:         ":80",
					AllowACMEByPass: false,
					ReusePort:       false,
					AsDefault:       false,
					Transport: &EntryPointsTransport{
						LifeCycle: &LifeCycle{
							GraceTimeOut: 10000000000,
						},
						RespondingTimeouts: &RespondingTimeouts{
							ReadTimeout: 60000000000,
							IdleTimeout: 180000000000,
						},
					},
					ProxyProtocol:    nil,
					ForwardedHeaders: &ForwardedHeaders{},
					HTTP: HTTPConfig{
						SanitizePath:   pointer(true),
						MaxHeaderBytes: 1048576,
					},
					HTTP2: &HTTP2Config{
						MaxConcurrentStreams:      250,
						MaxDecoderHeaderTableSize: 4096,
						MaxEncoderHeaderTableSize: 4096,
					},
					HTTP3: nil,
					UDP: &UDPConfig{
						Timeout: 3000000000,
					},
				}},
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"foo": {
						ACME: &acme.Configuration{
							CAServer: "https://acme-v02.api.letsencrypt.org/directory",
							DNSChallenge: &acme.DNSChallenge{
								Provider:         "bar",
								DelayBeforeCheck: 123,
								Propagation: &acme.Propagation{
									DelayBeforeChecks: 123,
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "ACME deprecation DisablePropagationCheck",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"foo": {
						ACME: &acme.Configuration{
							DNSChallenge: &acme.DNSChallenge{
								Provider:                "bar",
								DisablePropagationCheck: true,
							},
						},
					},
				},
			},
			expected: &Configuration{
				EntryPoints: EntryPoints{"http": &EntryPoint{
					Address:         ":80",
					AllowACMEByPass: false,
					ReusePort:       false,
					AsDefault:       false,
					Transport: &EntryPointsTransport{
						LifeCycle: &LifeCycle{
							GraceTimeOut: 10000000000,
						},
						RespondingTimeouts: &RespondingTimeouts{
							ReadTimeout: 60000000000,
							IdleTimeout: 180000000000,
						},
					},
					ProxyProtocol:    nil,
					ForwardedHeaders: &ForwardedHeaders{},
					HTTP: HTTPConfig{
						SanitizePath:   pointer(true),
						MaxHeaderBytes: 1048576,
					},
					HTTP2: &HTTP2Config{
						MaxConcurrentStreams:      250,
						MaxDecoderHeaderTableSize: 4096,
						MaxEncoderHeaderTableSize: 4096,
					},
					HTTP3: nil,
					UDP: &UDPConfig{
						Timeout: 3000000000,
					},
				}},
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"foo": {
						ACME: &acme.Configuration{
							CAServer: "https://acme-v02.api.letsencrypt.org/directory",
							DNSChallenge: &acme.DNSChallenge{
								Provider:                "bar",
								DisablePropagationCheck: true,
								Propagation: &acme.Propagation{
									DisableChecks: true,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			test.conf.SetEffectiveConfiguration()

			assert.Equal(t, test.expected, test.conf)
		})
	}
}

func TestConfiguration_ValidateConfiguration_ACMEKVStores(t *testing.T) {
	testCases := []struct {
		desc        string
		conf        *Configuration
		expectedErr string
	}{
		{
			desc: "No resolver configured",
			conf: &Configuration{
				Providers: &Providers{},
			},
			expectedErr: "",
		},
		{
			desc: "ACME with storage path only (valid)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Storage: "/path/to/acme.json",
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			desc: "ACME with Redis only (valid)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			desc: "ACME with Consul only (valid)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Consul: &acme.ConsulStoreConfig{
								Endpoints: []string{"localhost:8500"},
							},
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			desc: "ACME with Etcd only (valid)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Etcd: &acme.EtcdStoreConfig{
								Endpoints: []string{"localhost:2379"},
							},
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			desc: "ACME with Redis and Consul (mutually exclusive error)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
							Consul: &acme.ConsulStoreConfig{
								Endpoints: []string{"localhost:8500"},
							},
						},
					},
				},
			},
			expectedErr: "only one distributed store (redis, consul, etcd) can be configured at a time",
		},
		{
			desc: "ACME with Redis and Etcd (mutually exclusive error)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
							Etcd: &acme.EtcdStoreConfig{
								Endpoints: []string{"localhost:2379"},
							},
						},
					},
				},
			},
			expectedErr: "only one distributed store (redis, consul, etcd) can be configured at a time",
		},
		{
			desc: "ACME with Consul and Etcd (mutually exclusive error)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Consul: &acme.ConsulStoreConfig{
								Endpoints: []string{"localhost:8500"},
							},
							Etcd: &acme.EtcdStoreConfig{
								Endpoints: []string{"localhost:2379"},
							},
						},
					},
				},
			},
			expectedErr: "only one distributed store (redis, consul, etcd) can be configured at a time",
		},
		{
			desc: "ACME with all three KV stores (mutually exclusive error)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
							Consul: &acme.ConsulStoreConfig{
								Endpoints: []string{"localhost:8500"},
							},
							Etcd: &acme.EtcdStoreConfig{
								Endpoints: []string{"localhost:2379"},
							},
						},
					},
				},
			},
			expectedErr: "only one distributed store (redis, consul, etcd) can be configured at a time",
		},
		{
			desc: "ACME with no storage and no KV store (error)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Storage: "",
						},
					},
				},
			},
			expectedErr: "with no storage location for the certificates",
		},
		{
			desc: "ACME with KV store and empty storage (valid - storage not required)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Storage: "",
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
						},
					},
				},
			},
			expectedErr: "",
		},
		{
			desc: "Multiple resolvers - one valid, one with error",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"valid-resolver": {
						ACME: &acme.Configuration{
							Storage: "/path/to/acme.json",
						},
					},
					"invalid-resolver": {
						ACME: &acme.Configuration{
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
							Consul: &acme.ConsulStoreConfig{
								Endpoints: []string{"localhost:8500"},
							},
						},
					},
				},
			},
			expectedErr: "only one distributed store (redis, consul, etcd) can be configured at a time",
		},
		{
			desc: "ACME and Tailscale mutually exclusive",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME:      &acme.Configuration{},
						Tailscale: &struct{}{},
					},
				},
			},
			expectedErr: "ACME and Tailscale providers are mutually exclusive",
		},
		{
			desc: "Tailscale only (valid)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						Tailscale: &struct{}{},
					},
				},
			},
			expectedErr: "",
		},
		{
			desc: "ACME with KV store and storage both set (valid - KV takes precedence)",
			conf: &Configuration{
				Providers: &Providers{},
				CertificatesResolvers: map[string]CertificateResolver{
					"myresolver": {
						ACME: &acme.Configuration{
							Storage: "/path/to/acme.json",
							Redis: &acme.RedisStoreConfig{
								Endpoints: []string{"localhost:6379"},
							},
						},
					},
				},
			},
			expectedErr: "",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			err := test.conf.ValidateConfiguration()

			if test.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
			}
		})
	}
}

func TestConfiguration_ValidateConfiguration_MultipleResolvers(t *testing.T) {
	// Test that multiple resolvers can each have different KV store configurations
	conf := &Configuration{
		Providers: &Providers{},
		CertificatesResolvers: map[string]CertificateResolver{
			"redis-resolver": {
				ACME: &acme.Configuration{
					Redis: &acme.RedisStoreConfig{
						Endpoints: []string{"localhost:6379"},
					},
				},
			},
			"consul-resolver": {
				ACME: &acme.Configuration{
					Consul: &acme.ConsulStoreConfig{
						Endpoints: []string{"localhost:8500"},
					},
				},
			},
			"etcd-resolver": {
				ACME: &acme.Configuration{
					Etcd: &acme.EtcdStoreConfig{
						Endpoints: []string{"localhost:2379"},
					},
				},
			},
			"file-resolver": {
				ACME: &acme.Configuration{
					Storage: "/path/to/acme.json",
				},
			},
		},
	}

	err := conf.ValidateConfiguration()
	assert.NoError(t, err, "Each resolver can have a different KV store or file storage")
}
