package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/whalebone/dnsproxy/internal/bootstrap"
)

func TestUpstreamDoH(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		expectedProtocol HTTPVersion
		httpVersions     []HTTPVersion
		delayHandshakeH3 time.Duration
		delayHandshakeH2 time.Duration
		http3Enabled     bool
	}{{
		name:             "http1.1_h2",
		http3Enabled:     false,
		httpVersions:     []HTTPVersion{HTTPVersion11, HTTPVersion2},
		expectedProtocol: HTTPVersion2,
	}, {
		name:             "fallback_to_http2",
		http3Enabled:     false,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		expectedProtocol: HTTPVersion2,
	}, {
		name:             "http3",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3},
		expectedProtocol: HTTPVersion3,
	}, {
		name:             "race_http3_faster",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		delayHandshakeH2: time.Second,
		expectedProtocol: HTTPVersion3,
	}, {
		name:             "race_http2_faster",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		delayHandshakeH3: time.Second,
		expectedProtocol: HTTPVersion2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startDoHServer(t, testDoHServerOptions{
				http3Enabled:     tc.http3Enabled,
				delayHandshakeH2: tc.delayHandshakeH2,
				delayHandshakeH3: tc.delayHandshakeH3,
			})

			// Create a DNS-over-HTTPS upstream.
			address := fmt.Sprintf("https://%s/dns-query", srv.addr)

			var lastState tls.ConnectionState
			opts := &Options{
				Logger:             slogutil.NewDiscardLogger(),
				InsecureSkipVerify: true,
				HTTPVersions:       tc.httpVersions,
				VerifyConnection: func(state tls.ConnectionState) (err error) {
					if state.NegotiatedProtocol != string(tc.expectedProtocol) {
						return fmt.Errorf(
							"expected %s, got %s",
							tc.expectedProtocol,
							state.NegotiatedProtocol,
						)
					}
					lastState = state
					return nil
				},
			}
			u, err := AddressToUpstream(address, opts)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			// Test that it responds properly.
			for range 10 {
				checkUpstream(t, u, address)
			}

			doh := u.(*dnsOverHTTPS)

			// Trigger re-connection.
			doh.client = nil

			// Force it to establish the connection again.
			checkUpstream(t, u, address)

			// Check that TLS session was resumed properly.
			require.True(t, lastState.DidResume)
		})
	}
}

func TestUpstreamDoH_raceReconnect(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		expectedProtocol HTTPVersion
		httpVersions     []HTTPVersion
		delayHandshakeH3 time.Duration
		delayHandshakeH2 time.Duration
		http3Enabled     bool
	}{{
		name:             "http1.1_h2",
		http3Enabled:     false,
		httpVersions:     []HTTPVersion{HTTPVersion11, HTTPVersion2},
		expectedProtocol: HTTPVersion2,
	}, {
		name:             "fallback_to_http2",
		http3Enabled:     false,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		expectedProtocol: HTTPVersion2,
	}, {
		name:             "http3",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3},
		expectedProtocol: HTTPVersion3,
	}, {
		name:             "race_http3_faster",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		delayHandshakeH2: time.Second,
		expectedProtocol: HTTPVersion3,
	}, {
		name:             "race_http2_faster",
		http3Enabled:     true,
		httpVersions:     []HTTPVersion{HTTPVersion3, HTTPVersion2},
		delayHandshakeH3: time.Second,
		expectedProtocol: HTTPVersion2,
	}}

	// This is a different set of tests that are supposed to be run with -race.
	// The difference is that the HTTP handler here adds additional time.Sleep
	// call.  This call would trigger the HTTP client re-connection which is
	// important to test for race conditions.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const timeout = time.Millisecond * 100
			var requestsCount int32

			handlerFunc := createDoHHandlerFunc()
			mux := http.NewServeMux()
			mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
				newVal := atomic.AddInt32(&requestsCount, 1)
				if newVal%10 == 0 {
					time.Sleep(timeout * 2)
				}
				handlerFunc(w, r)
			})

			srv := startDoHServer(t, testDoHServerOptions{
				http3Enabled:     tc.http3Enabled,
				delayHandshakeH2: tc.delayHandshakeH2,
				delayHandshakeH3: tc.delayHandshakeH3,
				handler:          mux,
			})

			// Create a DNS-over-HTTPS upstream that will be used for the
			// race test.
			address := fmt.Sprintf("https://%s/dns-query", srv.addr)
			opts := &Options{
				Logger:             slogutil.NewDiscardLogger(),
				InsecureSkipVerify: true,
				HTTPVersions:       tc.httpVersions,
				Timeout:            timeout,
			}
			u, err := AddressToUpstream(address, opts)
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			checkRaceCondition(u)
		})
	}
}

func TestUpstreamDoH_serverRestart(t *testing.T) {
	testCases := []struct {
		name         string
		httpVersions []HTTPVersion
	}{{
		name:         "http2",
		httpVersions: []HTTPVersion{HTTPVersion11, HTTPVersion2},
	}, {
		name:         "http3",
		httpVersions: []HTTPVersion{HTTPVersion3},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var addr netip.AddrPort
			var upsAddr string
			var u Upstream

			t.Run("first_try", func(t *testing.T) {
				srv := startDoHServer(t, testDoHServerOptions{
					http3Enabled: true,
				})

				addr = netip.MustParseAddrPort(srv.addr)
				upsAddr = (&url.URL{
					Scheme: "https",
					Host:   addr.String(),
					Path:   "dns-query",
				}).String()

				var err error
				u, err = AddressToUpstream(upsAddr, &Options{
					Logger:             slogutil.NewDiscardLogger(),
					InsecureSkipVerify: true,
					HTTPVersions:       tc.httpVersions,
					Timeout:            100 * time.Millisecond,
				})
				require.NoError(t, err)

				checkUpstream(t, u, upsAddr)
			})
			require.False(t, t.Failed())
			testutil.CleanupAndRequireSuccess(t, u.Close)

			t.Run("second_try", func(t *testing.T) {
				_ = startDoHServer(t, testDoHServerOptions{
					http3Enabled: true,
					port:         int(addr.Port()),
				})

				checkUpstream(t, u, upsAddr)
			})
			require.False(t, t.Failed())

			t.Run("retry", func(t *testing.T) {
				_, err := u.Exchange(createTestMessage())
				require.Error(t, err)

				_ = startDoHServer(t, testDoHServerOptions{
					http3Enabled: true,
					port:         int(addr.Port()),
				})

				checkUpstream(t, u, upsAddr)
			})
		})
	}
}

func TestUpstreamDoH_0RTT(t *testing.T) {
	t.Parallel()

	// Run the first server instance.
	srv := startDoHServer(t, testDoHServerOptions{
		http3Enabled: true,
	})

	// Create a DNS-over-HTTPS upstream.
	tracer := &quicTracer{}
	address := fmt.Sprintf("h3://%s/dns-query", srv.addr)
	u, err := AddressToUpstream(address, &Options{
		Logger:             slogutil.NewDiscardLogger(),
		InsecureSkipVerify: true,
		QUICTracer:         tracer.TracerForConnection,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	uh := u.(*dnsOverHTTPS)
	req := createTestMessage()

	// Trigger connection to a DoH3 server.
	resp, err := uh.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)

	// Close the active connection to make sure we'll reconnect.
	func() {
		uh.clientMu.Lock()
		defer uh.clientMu.Unlock()

		err = uh.closeClient(uh.client)
		require.NoError(t, err)

		uh.client = nil
	}()

	// Trigger second connection.
	resp, err = uh.Exchange(req)
	require.NoError(t, err)
	requireResponse(t, req, resp)

	// Check traced connections info.
	conns := tracer.getConnectionsInfo()
	require.Len(t, conns, 2)

	// Examine the first connection (no 0-RTT there).
	require.False(t, conns[0].is0RTT())

	// Examine the second connection (the one that used 0-RTT).
	require.True(t, conns[1].is0RTT())
}

// testDoHServerOptions allows customizing testDoHServer behavior.
type testDoHServerOptions struct {
	// handler is an HTTP handler that should be used by the server.  The
	// default one is used on nil.
	handler http.Handler
	// delayHandshakeH2 is a delay that should be added to the handshake of the
	// HTTP/2 server.
	delayHandshakeH2 time.Duration
	// delayHandshakeH3 is a delay that should be added to the handshake of the
	// HTTP/3 server.
	delayHandshakeH3 time.Duration
	// port is the port that the server should listen to.  If it's 0, a random
	// port is used.
	port int
	// http3Enabled is a flag that indicates whether the server should start an
	// HTTP/3 server.
	http3Enabled bool
}

// testDoHServer is an instance of a test DNS-over-HTTPS server.
type testDoHServer struct {
	// tlsConfig is the TLS configuration that is used for this server.
	tlsConfig *tls.Config

	// rootCAs is the pool with root certificates used by the test server.
	rootCAs *x509.CertPool

	// server is an HTTP/1.1 and HTTP/2 server.
	server *http.Server

	// serverH3 is an HTTP/3 server.
	serverH3 *http3.Server

	// listenerH3 that's used to serve HTTP/3.
	listenerH3 *quic.EarlyListener

	// addr is the address that this server listens to.
	addr string
}

// Shutdown stops the DoH server.
func (s *testDoHServer) Shutdown() {
	if s.server != nil {
		_ = s.server.Shutdown(context.Background())
	}

	if s.serverH3 != nil {
		_ = s.serverH3.Close()
		_ = s.listenerH3.Close()
	}
}

// startDoHServer starts a new DNS-over-HTTPS server with specified options.  It
// returns a started server instance with addr set.  Note that it adds its own
// shutdown to cleanup of t.
func startDoHServer(
	t *testing.T,
	opts testDoHServerOptions,
) (s *testDoHServer) {
	tlsConfig, rootCAs := createServerTLSConfig(t, "127.0.0.1")
	handler := opts.handler
	if handler == nil {
		handler = createDoHHandler()
	}

	// Step one is to create a regular HTTP server, we'll always have it
	// running.
	server := &http.Server{
		Handler:     handler,
		ReadTimeout: time.Second,
		ErrorLog:    slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug),
	}

	// Listen TCP first.
	listenAddr := fmt.Sprintf("127.0.0.1:%d", opts.port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	require.NoError(t, err)

	tcpListen, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err)

	tlsConfigH2 := tlsConfig.Clone()
	tlsConfigH2.NextProtos = []string{string(HTTPVersion2), string(HTTPVersion11)}
	tlsConfigH2.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		if opts.delayHandshakeH2 > 0 {
			time.Sleep(opts.delayHandshakeH2)
		}
		return nil, nil
	}
	tlsListen := tls.NewListener(tcpListen, tlsConfigH2)

	// Run the H1/H2 server.
	go func() {
		// TODO(ameshkov): check the error here.
		_ = server.Serve(tlsListen)
	}()

	// Get the real address that the listener now listens to.
	tcpAddr = tcpListen.Addr().(*net.TCPAddr)

	var serverH3 *http3.Server
	var listenerH3 *quic.EarlyListener

	if opts.http3Enabled {
		tlsConfigH3 := tlsConfig.Clone()
		tlsConfigH3.NextProtos = []string{string(HTTPVersion3)}
		tlsConfigH3.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			if opts.delayHandshakeH3 > 0 {
				time.Sleep(opts.delayHandshakeH3)
			}
			return nil, nil
		}

		serverH3 = &http3.Server{
			Handler: handler,
		}

		// Listen UDP for the H3 server. Reuse the same port as was used for the
		// TCP listener.
		var udpAddr *net.UDPAddr
		udpAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port))
		require.NoError(t, err)

		var conn net.PacketConn
		conn, err = net.ListenUDP("udp", udpAddr)
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, conn.Close)

		transport := &quic.Transport{
			Conn:                conn,
			VerifySourceAddress: func(net.Addr) bool { return false },
		}

		// QUIC configuration with the 0-RTT support enabled by default.
		listenerH3, err = transport.ListenEarly(tlsConfigH3, &quic.Config{
			Allow0RTT: true,
		})
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, transport.Close)

		// Run the H3 server.
		go func() {
			// TODO(ameshkov): check the error here.
			_ = serverH3.ServeListener(listenerH3)
		}()
	}

	s = &testDoHServer{
		tlsConfig:  tlsConfig,
		rootCAs:    rootCAs,
		server:     server,
		serverH3:   serverH3,
		listenerH3: listenerH3,
		// Save the address that the server listens to.
		addr: tcpAddr.String(),
	}
	t.Cleanup(s.Shutdown)

	return s
}

// createDoHHandlerFunc creates a simple http.HandlerFunc that reads the
// incoming DNS message and returns the test response.
func createDoHHandlerFunc() (f http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request) {
		dnsParam := r.URL.Query().Get("dns")
		buf, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("internal error: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		m := &dns.Msg{}
		err = m.Unpack(buf)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("internal error: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		resp := respondToTestMessage(m)

		buf, err = resp.Pack()
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("internal error: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")

		_, err = w.Write(buf)
		if err != nil {
			panic(fmt.Errorf("unexpected error on writing response: %w", err))
		}
	}
}

// createDoHHandler returns a very simple http.Handler that reads the incoming
// request and returns with a test message.
func createDoHHandler() (h http.Handler) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", createDoHHandlerFunc())

	return mux
}

// testProxyTimeout is the upstream timeout used by the proxy tests, long
// enough not to fire before the assertion under test.
const testProxyTimeout = 5 * time.Second

func TestUpstreamDoH_proxy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		host                string
		bootstrap           Resolver
		wantConnects        int64
		useProxy            bool
		proxyReturnsURL     bool
		proxyResolvesTarget bool
	}{{
		name:                "through_proxy",
		host:                "",
		bootstrap:           nil,
		wantConnects:        1,
		useProxy:            true,
		proxyReturnsURL:     true,
		proxyResolvesTarget: false,
	}, {
		name:                "direct_without_proxy",
		host:                "",
		bootstrap:           nil,
		wantConnects:        0,
		useProxy:            false,
		proxyReturnsURL:     false,
		proxyResolvesTarget: false,
	}, {
		// A proxy func that returns no proxy must still reach the upstream
		// through its bootstrap, not through the system resolver.
		name:                "bootstrapped_host_without_proxy_url",
		host:                "dns.example",
		bootstrap:           StaticResolver{netip.MustParseAddr("127.0.0.1")},
		wantConnects:        0,
		useProxy:            true,
		proxyReturnsURL:     false,
		proxyResolvesTarget: false,
	}, {
		// The upstream's address must match the dial target through the
		// punycode conversion [http.Transport] applies, or the bootstrap
		// branch is silently skipped.
		name:                "idn_host_without_proxy_url",
		host:                "bücher.example",
		bootstrap:           StaticResolver{netip.MustParseAddr("127.0.0.1")},
		wantConnects:        0,
		useProxy:            true,
		proxyReturnsURL:     false,
		proxyResolvesTarget: false,
	}, {
		// [http.Transport] dials an ASCII host with its case preserved, while
		// [transportAddr] folds it, so the match must be case-insensitive.
		name:                "uppercase_host_without_proxy_url",
		host:                "DNS.EXAMPLE",
		bootstrap:           StaticResolver{netip.MustParseAddr("127.0.0.1")},
		wantConnects:        0,
		useProxy:            true,
		proxyReturnsURL:     false,
		proxyResolvesTarget: false,
	}, {
		// A proxied request needs no bootstrap at all, since the proxy resolves
		// the upstream's hostname itself.  So a host that this machine cannot
		// resolve, and no bootstrap to resolve it with, must still work.
		name:                "unresolvable_host_through_proxy",
		host:                "unresolvable.invalid",
		bootstrap:           nil,
		wantConnects:        1,
		useProxy:            true,
		proxyReturnsURL:     true,
		proxyResolvesTarget: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := startDoHServer(t, testDoHServerOptions{})

			srvAddr := srv.addr
			if tc.host != "" {
				_, port, err := net.SplitHostPort(srv.addr)
				require.NoError(t, err)

				srvAddr = net.JoinHostPort(tc.host, port)
			}

			proxyTarget := ""
			if tc.proxyResolvesTarget {
				proxyTarget = srv.addr
			}

			prx := startTestHTTPProxy(t, proxyTarget)

			var proxyFunc ProxyFunc
			if tc.useProxy {
				proxyFunc = func(_ *http.Request) (proxyURL *url.URL, err error) {
					if !tc.proxyReturnsURL {
						return nil, nil
					}

					return prx.url, nil
				}
			}

			address := fmt.Sprintf("https://%s/dns-query", srvAddr)
			u, err := AddressToUpstream(address, &Options{
				Logger:             slogutil.NewDiscardLogger(),
				InsecureSkipVerify: true,
				Bootstrap:          tc.bootstrap,
				Proxy:              proxyFunc,
			})
			require.NoError(t, err)
			testutil.CleanupAndRequireSuccess(t, u.Close)

			checkUpstream(t, u, address)

			assert.Equal(t, tc.wantConnects, prx.connects.Load())
		})
	}
}

// TestCheckProxyScheme asserts that the checked proxy func rejects the URL
// schemes [http.Transport] would connect to with this upstream's own TLS
// configuration, and passes everything else through untouched.
func TestCheckProxyScheme(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		scheme     string
		wantErrMsg string
	}{{
		name:       "empty",
		scheme:     "",
		wantErrMsg: "",
	}, {
		name:       "http",
		scheme:     "http",
		wantErrMsg: "",
	}, {
		name:       "socks5",
		scheme:     "socks5",
		wantErrMsg: "",
	}, {
		name:       "socks5h",
		scheme:     "socks5h",
		wantErrMsg: "",
	}, {
		name:       "https",
		scheme:     "https",
		wantErrMsg: `proxy scheme "https" is not supported`,
	}, {
		name:       "ftp",
		scheme:     "ftp",
		wantErrMsg: `proxy scheme "ftp" is not supported`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := &url.URL{Scheme: tc.scheme, Host: "proxy.example:3128"}
			checked := checkProxyScheme(func(_ *http.Request) (proxyURL *url.URL, err error) {
				return in, nil
			})

			out, err := checked(nil)

			if tc.wantErrMsg == "" {
				require.NoError(t, err)
				assert.Same(t, in, out)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErrMsg, err.Error())
				assert.Nil(t, out)
			}
		})
	}

	t.Run("nil_func", func(t *testing.T) {
		t.Parallel()

		assert.Nil(t, checkProxyScheme(nil))
	})

	t.Run("no_proxy", func(t *testing.T) {
		t.Parallel()

		checked := checkProxyScheme(func(_ *http.Request) (proxyURL *url.URL, err error) {
			return nil, nil
		})

		out, err := checked(nil)

		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		checked := checkProxyScheme(func(_ *http.Request) (proxyURL *url.URL, err error) {
			return nil, assert.AnError
		})

		_, err := checked(nil)

		assert.ErrorIs(t, err, assert.AnError)
	})
}

// TestUpstreamDoH_proxyScheme asserts the scheme handling end to end: a proxy
// URL with no scheme, which is what the Windows PAC resolution produces, is
// used as a plain HTTP proxy, while an https one is rejected before any
// connection is made.
func TestUpstreamDoH_proxyScheme(t *testing.T) {
	t.Parallel()

	srv := startDoHServer(t, testDoHServerOptions{})
	address := fmt.Sprintf("https://%s/dns-query", srv.addr)

	t.Run("empty_scheme_via_proxy", func(t *testing.T) {
		t.Parallel()

		prx := startTestHTTPProxy(t, "")

		u, err := AddressToUpstream(address, &Options{
			Logger:             slogutil.NewDiscardLogger(),
			InsecureSkipVerify: true,
			Proxy: func(_ *http.Request) (proxyURL *url.URL, err error) {
				return &url.URL{Host: prx.url.Host}, nil
			},
		})
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, u.Close)

		checkUpstream(t, u, address)

		assert.Equal(t, int64(1), prx.connects.Load())
	})

	t.Run("https_scheme_rejected", func(t *testing.T) {
		t.Parallel()

		u, err := AddressToUpstream(address, &Options{
			Logger:             slogutil.NewDiscardLogger(),
			InsecureSkipVerify: true,
			Timeout:            testProxyTimeout,
			Proxy: func(_ *http.Request) (proxyURL *url.URL, err error) {
				return &url.URL{Scheme: "https", Host: "proxy.invalid:3128"}, nil
			},
		})
		require.NoError(t, err)
		testutil.CleanupAndRequireSuccess(t, u.Close)

		_, err = u.Exchange(createTestMessage())

		require.Error(t, err)
		assert.Contains(t, err.Error(), `proxy scheme "https" is not supported`)
	})
}

// TestUpstreamDoH_proxyDirectBootstrapFailure asserts that deferring the
// bootstrap of a proxied upstream doesn't swallow its failure: a request that
// the proxy func sends directly still reports that the upstream could not be
// bootstrapped.
func TestUpstreamDoH_proxyDirectBootstrapFailure(t *testing.T) {
	t.Parallel()

	u, err := AddressToUpstream("https://dns.example/dns-query", &Options{
		Logger:    slogutil.NewDiscardLogger(),
		Bootstrap: errTestResolver{},
		Timeout:   testProxyTimeout,
		Proxy: func(_ *http.Request) (proxyURL *url.URL, err error) {
			return nil, nil
		},
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	_, err = u.Exchange(createTestMessage())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrapping")
}

// TestUpstreamDoH_proxyThenDirect asserts that an upstream which has already
// served a proxied request can still fall back to a direct one, initializing
// its bootstrap only then.
//
// Note that [Options.Proxy] is consulted only when a new connection is needed,
// not per request: with HTTP/2 the established tunnel is reused for the same
// authority whatever the proxy func says.  So the test closes it in between.
func TestUpstreamDoH_proxyThenDirect(t *testing.T) {
	t.Parallel()

	srv := startDoHServer(t, testDoHServerOptions{})
	prx := startTestHTTPProxy(t, srv.addr)

	_, port, err := net.SplitHostPort(srv.addr)
	require.NoError(t, err)

	// Use a hostname that only the bootstrap can resolve, so that the direct
	// request cannot succeed without it.
	address := fmt.Sprintf("https://%s/dns-query", net.JoinHostPort("dns.example", port))

	proxied := &atomic.Bool{}
	proxied.Store(true)

	u, err := AddressToUpstream(address, &Options{
		Logger:             slogutil.NewDiscardLogger(),
		InsecureSkipVerify: true,
		Bootstrap:          StaticResolver{netip.MustParseAddr("127.0.0.1")},
		Proxy: func(_ *http.Request) (proxyURL *url.URL, err error) {
			if !proxied.Load() {
				return nil, nil
			}

			return prx.url, nil
		},
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	checkUpstream(t, u, address)
	require.Equal(t, int64(1), prx.connects.Load())

	transport := testutil.RequireTypeAssert[*http.Transport](t, u.(*dnsOverHTTPS).client.Transport)
	transport.CloseIdleConnections()
	proxied.Store(false)

	checkUpstream(t, u, address)

	assert.Equal(t, int64(1), prx.connects.Load())
}

// TestUpstreamDoH_directThenProxy pins that a pooled HTTP/2 connection
// bypasses [Options.Proxy] in the direction that matters for policy: an
// upstream that has served a direct request keeps using the pooled connection
// even after the proxy func starts returning a proxy.  A consumer whose proxy
// configuration changed must close this upstream and create a new one.
//
// If a Go or x/net update starts consulting the proxy func on the pooled
// path, this test fails, surfacing the semantics change instead of letting it
// happen silently.
func TestUpstreamDoH_directThenProxy(t *testing.T) {
	t.Parallel()

	srv := startDoHServer(t, testDoHServerOptions{})
	prx := startTestHTTPProxy(t, srv.addr)

	address := fmt.Sprintf("https://%s/dns-query", srv.addr)

	proxied := &atomic.Bool{}

	u, err := AddressToUpstream(address, &Options{
		Logger:             slogutil.NewDiscardLogger(),
		InsecureSkipVerify: true,
		Proxy: func(_ *http.Request) (proxyURL *url.URL, err error) {
			if !proxied.Load() {
				return nil, nil
			}

			return prx.url, nil
		},
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, u.Close)

	checkUpstream(t, u, address)
	require.Equal(t, int64(0), prx.connects.Load())

	proxied.Store(true)

	checkUpstream(t, u, address)

	assert.Equal(t, int64(0), prx.connects.Load())
}

// TestTransportAddr asserts that the address [transportAddr] derives matches
// what [http.Transport] dials, over the host shapes that differ under the
// conversion: internationalized names, punycode, case, and the hosts the
// lookup profile rejects, which must fall back to the verbatim host.
func TestTransportAddr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		host string
		want string
	}{{
		name: "ascii",
		host: "dns.example:443",
		want: "dns.example:443",
	}, {
		name: "ascii_upper",
		host: "DNS.EXAMPLE:443",
		want: "dns.example:443",
	}, {
		name: "trailing_dot",
		host: "dns.example.:443",
		want: "dns.example.:443",
	}, {
		name: "punycode",
		host: "xn--bcher-kva.example:443",
		want: "xn--bcher-kva.example:443",
	}, {
		name: "punycode_upper",
		host: "XN--BCHER-KVA.example:443",
		want: "xn--bcher-kva.example:443",
	}, {
		name: "idn",
		host: "bücher.example:443",
		want: "xn--bcher-kva.example:443",
	}, {
		name: "idn_nontransitional",
		host: "faß.de:443",
		want: "xn--fa-hia.de:443",
	}, {
		name: "underscore_label",
		host: "_dmarc.example.com:443",
		want: "_dmarc.example.com:443",
	}, {
		name: "leading_hyphen_label",
		host: "-foo.example:443",
		want: "-foo.example:443",
	}, {
		name: "empty_label",
		host: "foo..example:443",
		want: "foo..example:443",
	}, {
		name: "invalid_punycode",
		host: "xn--a.example:443",
		want: "xn--a.example:443",
	}, {
		name: "ipv4",
		host: "127.0.0.1:443",
		want: "127.0.0.1:443",
	}, {
		name: "ipv6",
		host: "[::1]:443",
		want: "[::1]:443",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u := &url.URL{Host: tc.host}

			assert.Equal(t, tc.want, transportAddr(u))
		})
	}
}

// errTestResolver is a [Resolver] that always fails.  It exercises bootstrap
// failures without depending on the resolver of the machine running the test.
type errTestResolver struct{}

// type check
var _ Resolver = errTestResolver{}

// LookupNetIP implements the [Resolver] interface for errTestResolver.
func (errTestResolver) LookupNetIP(
	_ context.Context,
	_ bootstrap.Network,
	_ string,
) (addrs []netip.Addr, err error) {
	return nil, errors.Error("test resolver failure")
}

func TestUpstreamDoH_proxyRejectsHTTP3(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		address      string
		httpVersions []HTTPVersion
	}{{
		name:         "http_versions",
		address:      "https://dns.example/dns-query",
		httpVersions: []HTTPVersion{HTTPVersion3, HTTPVersion2},
	}, {
		name:         "h3_scheme",
		address:      "h3://dns.example/dns-query",
		httpVersions: nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := AddressToUpstream(tc.address, &Options{
				Logger:       slogutil.NewDiscardLogger(),
				HTTPVersions: tc.httpVersions,
				Proxy: func(_ *http.Request) (proxyURL *url.URL, err error) {
					return nil, nil
				},
			})

			testutil.AssertErrorMsg(t, "proxy is not supported for http/3", err)
		})
	}
}

// testHTTPProxy is a test HTTP proxy that tunnels CONNECT requests to their
// target and counts them.
type testHTTPProxy struct {
	// url is the address of this proxy, ready to be returned from
	// [Options.Proxy].
	url *url.URL

	// connects counts the CONNECT requests that reached this proxy.
	connects *atomic.Int64

	// target is the address to tunnel to, regardless of what the CONNECT
	// request asks for.  If empty, the request's own host is used.
	target string
}

// startTestHTTPProxy starts an HTTP proxy on a random port.  If target is not
// empty, the proxy tunnels to it instead of to the host of the CONNECT request,
// emulating a proxy that resolves the target's hostname itself.  Note that it
// adds its own shutdown to the cleanup of t.
func startTestHTTPProxy(t *testing.T, target string) (p *testHTTPProxy) {
	t.Helper()

	p = &testHTTPProxy{
		target:   target,
		connects: &atomic.Int64{},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{
		Handler:  http.HandlerFunc(p.serveHTTP),
		ErrorLog: slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug),
	}

	go func() {
		_ = srv.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
	})

	p.url = &url.URL{
		Scheme: "http",
		Host:   listener.Addr().String(),
	}

	return p
}

// serveHTTP tunnels a CONNECT request to r.Host and shuttles bytes in both
// directions until either side closes the connection.
func (p *testHTTPProxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only connect is supported", http.StatusMethodNotAllowed)

		return
	}

	p.connects.Add(1)

	targetAddr := p.target
	if targetAddr == "" {
		targetAddr = r.Host
	}

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)

		return
	}
	defer func() {
		_ = targetConn.Close()
	}()

	clientConn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
	defer func() {
		_ = clientConn.Close()
	}()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(targetConn, clientConn)
	}()

	_, _ = io.Copy(clientConn, targetConn)
}
