package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/provider/acme"
)

// FooCert is a PEM-encoded TLS cert.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host foo.org,foo.com  --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
const fooCert = `-----BEGIN CERTIFICATE-----
MIICHzCCAYigAwIBAgIQXQFLeYRwc5X21t457t2xADANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDCjn67GSs/khuGC4GNN+tVo1S+/eSHwr/hWzhfMqO7nYiXkFzmxi+u14CU
Pda6WOeps7T2/oQEFMxKKg7zYOqkLSbjbE0ZfosopaTvEsZm/AZHAAvoOrAsIJOn
SEiwy8h0tLA4z1SNR6rmIVQWyqBZEPAhBTQM1z7tFp48FakCFwIDAQABo3QwcjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUDHG3ASzeUezElup9zbPpBn/vjogwGwYDVR0RBBQwEoIH
Zm9vLm9yZ4IHZm9vLmNvbTANBgkqhkiG9w0BAQsFAAOBgQBT+VLMbB9u27tBX8Aw
ZrGY3rbNdBGhXVTksrjiF+6ZtDpD3iI56GH9zLxnqvXkgn3u0+Ard5TqF/xmdwVw
NY0V/aWYfcL2G2auBCQrPvM03ozRnVUwVfP23eUzX2ORNHCYhd2ObQx4krrhs7cJ
SWxtKwFlstoXY3K2g9oRD9UxdQ==
-----END CERTIFICATE-----`

// BarCert is a PEM-encoded TLS cert.
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host bar.org,bar.com  --ca --start-date "Jan 1 00:00:00 1970" --duration=10000h
const barCert = `-----BEGIN CERTIFICATE-----
MIICHTCCAYagAwIBAgIQcuIcNEXzBHPoxna5S6wG4jANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTcwMDEwMTAwMDAwMFoXDTcxMDIyMTE2MDAw
MFowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAqtcrP+KA7D6NjyztGNIPMup9KiBMJ8QL+preog/YHR7SQLO3kGFhpS3WKMab
SzMypC3ZX1PZjBP5ZzwaV3PFbuwlCkPlyxR2lOWmullgI7mjY0TBeYLDIclIzGRp
mpSDDSpkW1ay2iJDSpXjlhmwZr84hrCU7BRTQJo91fdsRTsCAwEAAaN0MHIwDgYD
VR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFK8jnzFQvBAgWtfzOyXY4VSkwrTXMBsGA1UdEQQUMBKCB2Jh
ci5vcmeCB2Jhci5jb20wDQYJKoZIhvcNAQELBQADgYEAJz0ifAExisC/ZSRhWuHz
7qs1i6Nd4+YgEVR8dR71MChP+AMxucY1/ajVjb9xlLys3GPE90TWSdVppabEVjZY
Oq11nPKc50ItTt8dMku6t0JHBmzoGdkN0V4zJCBqdQJxhop8JpYJ0S9CW0eT93h3
ipYQSsmIINGtMXJ8VkP/MlM=
-----END CERTIFICATE-----`

type gaugeMock struct {
	metrics map[string]float64
	labels  string
}

func (g gaugeMock) With(labelValues ...string) metrics.Gauge {
	g.labels = strings.Join(labelValues, ",")
	return g
}

func (g gaugeMock) Set(value float64) {
	g.metrics[g.labels] = value
}

func (g gaugeMock) Add(delta float64) {
	panic("implement me")
}

func TestAppendCertMetric(t *testing.T) {
	testCases := []struct {
		desc     string
		certs    []string
		expected map[string]float64
	}{
		{
			desc:     "No certs",
			certs:    []string{},
			expected: map[string]float64{},
		},
		{
			desc:  "One cert",
			certs: []string{fooCert},
			expected: map[string]float64{
				"cn,,serial,123624926713171615935660664614975025408,sans,foo.com,foo.org": 3.6e+09,
			},
		},
		{
			desc:  "Two certs",
			certs: []string{fooCert, barCert},
			expected: map[string]float64{
				"cn,,serial,123624926713171615935660664614975025408,sans,foo.com,foo.org": 3.6e+09,
				"cn,,serial,152706022658490889223053211416725817058,sans,bar.com,bar.org": 3.6e+07,
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			gauge := &gaugeMock{
				metrics: map[string]float64{},
			}

			for _, cert := range test.certs {
				block, _ := pem.Decode([]byte(cert))
				parsedCert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)

				appendCertMetric(gauge, parsedCert)
			}

			assert.Equal(t, test.expected, gauge.metrics)
		})
	}
}

func TestGetDefaultsEntrypoints(t *testing.T) {
	testCases := []struct {
		desc        string
		entrypoints static.EntryPoints
		expected    []string
	}{
		{
			desc: "Skips special names",
			entrypoints: map[string]*static.EntryPoint{
				"web": {
					Address: ":80",
				},
				"traefik": {
					Address: ":8080",
				},
			},
			expected: []string{"web"},
		},
		{
			desc: "Two EntryPoints not attachable",
			entrypoints: map[string]*static.EntryPoint{
				"web": {
					Address: ":80",
				},
				"websecure": {
					Address: ":443",
				},
			},
			expected: []string{"web", "websecure"},
		},
		{
			desc: "Two EntryPoints only one attachable",
			entrypoints: map[string]*static.EntryPoint{
				"web": {
					Address: ":80",
				},
				"websecure": {
					Address:   ":443",
					AsDefault: true,
				},
			},
			expected: []string{"websecure"},
		},
		{
			desc: "Two attachable EntryPoints",
			entrypoints: map[string]*static.EntryPoint{
				"web": {
					Address:   ":80",
					AsDefault: true,
				},
				"websecure": {
					Address:   ":443",
					AsDefault: true,
				},
			},
			expected: []string{"web", "websecure"},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			actual := getDefaultsEntrypoints(&static.Configuration{
				EntryPoints: test.entrypoints,
			})

			assert.ElementsMatch(t, test.expected, actual)
		})
	}
}

// TestResponseRecorder tests the responseRecorder buffering and flush behavior.
func TestResponseRecorder(t *testing.T) {
	testCases := []struct {
		desc           string
		writeHeader    bool
		statusCode     int
		body           []byte
		expectedStatus int
		expectedBody   string
	}{
		{
			desc:           "WriteHeader only",
			writeHeader:    true,
			statusCode:     http.StatusOK,
			body:           nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			desc:           "Write body without WriteHeader (implicit 200)",
			writeHeader:    false,
			statusCode:     0,
			body:           []byte("test body"),
			expectedStatus: http.StatusOK,
			expectedBody:   "test body",
		},
		{
			desc:           "WriteHeader and Write body",
			writeHeader:    true,
			statusCode:     http.StatusOK,
			body:           []byte("challenge response"),
			expectedStatus: http.StatusOK,
			expectedBody:   "challenge response",
		},
		{
			desc:           "404 status",
			writeHeader:    true,
			statusCode:     http.StatusNotFound,
			body:           nil,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "",
		},
		{
			desc:           "500 status with body",
			writeHeader:    true,
			statusCode:     http.StatusInternalServerError,
			body:           []byte("error"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "error",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			// Create a mock ResponseWriter to verify flush behavior
			mockRW := &mockResponseWriter{header: http.Header{}}
			rec := &responseRecorder{
				ResponseWriter: mockRW,
				statusCode:     http.StatusNotFound, // default
			}

			// Simulate handler behavior
			if test.writeHeader {
				rec.WriteHeader(test.statusCode)
			}
			if test.body != nil {
				_, err := rec.Write(test.body)
				require.NoError(t, err)
			}

			// Before flush, nothing should be written to underlying writer
			assert.Equal(t, 0, mockRW.writtenStatus)
			assert.Empty(t, mockRW.writtenBody)

			// Flush should write to underlying writer
			rec.flush()

			if test.writeHeader || test.body != nil {
				assert.Equal(t, test.expectedStatus, mockRW.writtenStatus)
			}
			assert.Equal(t, test.expectedBody, string(mockRW.writtenBody))
		})
	}
}

// TestResponseRecorderMultipleWrites tests multiple writes are buffered correctly.
func TestResponseRecorderMultipleWrites(t *testing.T) {
	mockRW := &mockResponseWriter{header: http.Header{}}
	rec := &responseRecorder{
		ResponseWriter: mockRW,
		statusCode:     http.StatusNotFound,
	}

	// Write multiple chunks
	_, err := rec.Write([]byte("chunk1"))
	require.NoError(t, err)
	_, err = rec.Write([]byte("chunk2"))
	require.NoError(t, err)
	_, err = rec.Write([]byte("chunk3"))
	require.NoError(t, err)

	// Nothing written yet
	assert.Empty(t, mockRW.writtenBody)

	// Status should be implicitly set to 200 after first write
	assert.Equal(t, http.StatusOK, rec.statusCode)

	// Flush
	rec.flush()

	assert.Equal(t, http.StatusOK, mockRW.writtenStatus)
	assert.Equal(t, "chunk1chunk2chunk3", string(mockRW.writtenBody))
}

// TestResponseRecorderWriteHeaderOnlyOnce tests that WriteHeader only takes effect once.
func TestResponseRecorderWriteHeaderOnlyOnce(t *testing.T) {
	mockRW := &mockResponseWriter{header: http.Header{}}
	rec := &responseRecorder{
		ResponseWriter: mockRW,
		statusCode:     http.StatusNotFound,
	}

	rec.WriteHeader(http.StatusOK)
	rec.WriteHeader(http.StatusInternalServerError) // Should be ignored

	assert.Equal(t, http.StatusOK, rec.statusCode)
}

// mockResponseWriter is a mock implementation of http.ResponseWriter for testing.
type mockResponseWriter struct {
	header        http.Header
	writtenStatus int
	writtenBody   []byte
}

func (m *mockResponseWriter) Header() http.Header {
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.writtenBody = append(m.writtenBody, b...)
	return len(b), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.writtenStatus = statusCode
}

// TestCompositeHTTPChallengeHandler tests the composite handler behavior.
func TestCompositeHTTPChallengeHandler(t *testing.T) {
	testCases := []struct {
		desc           string
		handlers       []http.Handler
		fallback       http.Handler
		expectedStatus int
		expectedBody   string
	}{
		{
			desc: "First handler succeeds",
			handlers: []http.Handler{
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte("handler1"))
				}),
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte("handler2"))
				}),
			},
			fallback:       nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "handler1",
		},
		{
			desc: "Second handler succeeds after first fails",
			handlers: []http.Handler{
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusNotFound)
				}),
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
					_, _ = rw.Write([]byte("handler2"))
				}),
			},
			fallback:       nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "handler2",
		},
		{
			desc: "All handlers fail, fallback succeeds",
			handlers: []http.Handler{
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusNotFound)
				}),
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusNotFound)
				}),
			},
			fallback: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write([]byte("fallback"))
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   "fallback",
		},
		{
			desc: "All handlers fail, no fallback returns 404",
			handlers: []http.Handler{
				http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusNotFound)
				}),
			},
			fallback:       nil,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "",
		},
		{
			desc:     "No handlers, use fallback",
			handlers: []http.Handler{},
			fallback: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
				_, _ = rw.Write([]byte("fallback only"))
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   "fallback only",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			composite := &compositeHTTPChallengeHandler{
				handlers: test.handlers,
				fallback: test.fallback,
			}

			mockRW := &mockResponseWriter{header: http.Header{}}
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token", nil)

			composite.ServeHTTP(mockRW, req)

			assert.Equal(t, test.expectedStatus, mockRW.writtenStatus)
			assert.Equal(t, test.expectedBody, string(mockRW.writtenBody))
		})
	}
}

// TestGetHTTPChallengeHandler tests the getHTTPChallengeHandler function returns correct handler.
func TestGetHTTPChallengeHandler(t *testing.T) {
	testCases := []struct {
		desc            string
		providers       []*acme.Provider
		expectedType    string
		expectedHandler bool
	}{
		{
			desc:            "No providers returns fallback",
			providers:       []*acme.Provider{},
			expectedType:    "fallback",
			expectedHandler: true,
		},
		{
			desc: "Single provider with no HTTP challenge returns fallback",
			providers: []*acme.Provider{
				{Configuration: &acme.Configuration{}},
			},
			expectedType:    "fallback",
			expectedHandler: true,
		},
		{
			desc: "Single provider with HTTP challenge but nil HTTPChallengeProvider returns fallback",
			providers: []*acme.Provider{
				{
					Configuration: &acme.Configuration{
						HTTPChallenge: &acme.HTTPChallenge{},
					},
					HTTPChallengeProvider: nil,
				},
			},
			expectedType:    "fallback",
			expectedHandler: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			fallbackHandler := acme.NewChallengeHTTP()
			handler := getHTTPChallengeHandler(test.providers, fallbackHandler)

			assert.NotNil(t, handler)
			if test.expectedType == "fallback" {
				assert.Equal(t, fallbackHandler, handler)
			}
		})
	}
}

// TestGetHTTPChallengeHandlerWithDistributedProvider tests handler selection with distributed providers.
func TestGetHTTPChallengeHandlerWithDistributedProvider(t *testing.T) {
	fallbackHandler := acme.NewChallengeHTTP()

	// Test with standard ChallengeHTTP provider
	stdChallenge := acme.NewChallengeHTTP()
	providers := []*acme.Provider{
		{
			Configuration: &acme.Configuration{
				HTTPChallenge: &acme.HTTPChallenge{},
			},
			HTTPChallengeProvider: stdChallenge,
		},
	}

	handler := getHTTPChallengeHandler(providers, fallbackHandler)
	assert.NotNil(t, handler)
	// Should return the single handler directly
	assert.Equal(t, stdChallenge, handler)
}

// TestGetHTTPChallengeHandlerMultipleProviders tests composite handler creation.
func TestGetHTTPChallengeHandlerMultipleProviders(t *testing.T) {
	fallbackHandler := acme.NewChallengeHTTP()

	stdChallenge1 := acme.NewChallengeHTTP()
	stdChallenge2 := acme.NewChallengeHTTP()
	providers := []*acme.Provider{
		{
			Configuration: &acme.Configuration{
				HTTPChallenge: &acme.HTTPChallenge{},
			},
			HTTPChallengeProvider: stdChallenge1,
		},
		{
			Configuration: &acme.Configuration{
				HTTPChallenge: &acme.HTTPChallenge{},
			},
			HTTPChallengeProvider: stdChallenge2,
		},
	}

	handler := getHTTPChallengeHandler(providers, fallbackHandler)
	assert.NotNil(t, handler)

	// Should return a composite handler
	composite, ok := handler.(*compositeHTTPChallengeHandler)
	assert.True(t, ok, "Expected compositeHTTPChallengeHandler")
	assert.Len(t, composite.handlers, 2)
	assert.Equal(t, fallbackHandler, composite.fallback)
}
