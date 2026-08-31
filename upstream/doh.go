package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/whalebone/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	// transportDefaultReadIdleTimeout is the default timeout for pinging
	// idle connections in HTTP/2 transport.
	transportDefaultReadIdleTimeout = 30 * time.Second

	// transportDefaultIdleConnTimeout is the default timeout for idle
	// connections in HTTP transport.
	transportDefaultIdleConnTimeout = 5 * time.Minute

	// dohMaxConnsPerHost controls the maximum number of connections for
	// each host.  Note, that setting it to 1 may cause issues with Go's http
	// implementation, see https://github.com/AdguardTeam/dnsproxy/issues/278.
	dohMaxConnsPerHost = 2

	// dohMaxIdleConns controls the maximum number of connections being idle
	// at the same time.
	dohMaxIdleConns = 2
)

// errProxyH3 is returned when a DNS-over-HTTPS upstream is configured with both
// a proxy and HTTP/3.  QUIC cannot traverse an HTTP CONNECT proxy, so allowing
// both would send the queries around the proxy instead of through it.
const errProxyH3 errors.Error = "proxy is not supported for http/3"

// dnsOverHTTPS is a struct that implements the Upstream interface for the
// DNS-over-HTTPS protocol.
type dnsOverHTTPS struct {
	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// proxy returns the proxy to send a request through, or nil for a direct
	// connection.  It is nil if no proxy is configured at all.
	proxy ProxyFunc

	// addr is the DNS-over-HTTPS server URL.
	addr *url.URL

	// tlsConf is the configuration of TLS.
	tlsConf *tls.Config

	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as needed.
	// Clients are safe for concurrent use by multiple goroutines.
	client *http.Client

	// clientMu protects client.
	clientMu *sync.Mutex

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// quicConf is the QUIC configuration that is used if HTTP/3 is enabled
	// for this upstream.
	quicConf *quic.Config

	// quicConfMu protects quicConf.
	quicConfMu *sync.Mutex

	// transportH2 is an HTTP/2 transport if any.
	transportH2 *http2.Transport

	// addrRedacted is the redacted string representation of addr.  It is saved
	// separately to reduce allocations during logging and error reporting.
	addrRedacted string

	// timeout is used in HTTP client and for H3 probes.
	timeout time.Duration
}

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoH(addr *url.URL, opts *Options) (u Upstream, err error) {
	addPort(addr, defaultPortDoH)

	var httpVersions []HTTPVersion
	if addr.Scheme == "h3" {
		addr.Scheme = "https"
		httpVersions = []HTTPVersion{HTTPVersion3}
	} else if httpVersions = opts.HTTPVersions; len(opts.HTTPVersions) == 0 {
		httpVersions = DefaultHTTPVersions
	}

	if opts.Proxy != nil && slices.Contains(httpVersions, HTTPVersion3) {
		return nil, errProxyH3
	}

	tlsConf := &tls.Config{
		ServerName:   addr.Hostname(),
		RootCAs:      opts.RootCAs,
		CipherSuites: opts.CipherSuites,
		// Use the default capacity for the LRU cache.  It may be useful to
		// store several caches since the user may be routed to different
		// servers in case there's load balancing on the server-side.
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		MinVersion:         tls.VersionTLS12,
		// #nosec G402 -- TLS certificate verification could be disabled by
		// configuration.
		InsecureSkipVerify:    opts.InsecureSkipVerify,
		VerifyPeerCertificate: opts.VerifyServerCertificate,
		VerifyConnection:      opts.VerifyConnection,
	}

	// Load client certificate if provided
	if opts.ClientCertPath != "" && opts.ClientKeyPath != "" {
		clientCert, err := tls.LoadX509KeyPair(opts.ClientCertPath, opts.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{clientCert}
	}

	ups := &dnsOverHTTPS{
		getDialer: newDialerInitializer(addr, opts),
		proxy:     checkProxyScheme(opts.Proxy),
		addr:      addr,
		quicConf: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
			Tracer:          opts.QUICTracer,
		},
		quicConfMu:   &sync.Mutex{},
		tlsConf:      tlsConf,
		clientMu:     &sync.Mutex{},
		logger:       opts.Logger,
		addrRedacted: addr.Redacted(),
		timeout:      opts.Timeout,
	}
	for _, v := range httpVersions {
		ups.tlsConf.NextProtos = append(ups.tlsConf.NextProtos, string(v))
	}

	runtime.SetFinalizer(ups, (*dnsOverHTTPS).Close)

	return ups, nil
}

// type check
var _ Upstream = (*dnsOverHTTPS)(nil)

// Address implements the [Upstream] interface for *dnsOverHTTPS.  The address
// is redacted: if the original URL of this upstream contains a userinfo with a
// password, the password is replaced with "xxxxx".
func (p *dnsOverHTTPS) Address() string { return p.addrRedacted }

// Exchange implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such as
	// "application/dns-message", SHOULD use a DNS ID of 0 in every DNS request.
	//
	// See https://www.rfc-editor.org/rfc/rfc8484.html.
	id := req.Id
	req.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies.
		req.Id = id
		if resp != nil {
			resp.Id = id
		}
	}()

	// Check if there was already an active client before sending the request.
	// We'll only attempt to re-connect if there was one.
	client, isCached, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to init http client: %w", err)
	}

	// Make the first attempt to send the DNS query.
	resp, err = p.exchangeHTTPS(client, req)

	// Make up to 2 attempts to re-create the HTTP client and send the request
	// again.  There are several cases (mostly, with QUIC) where this workaround
	// is necessary to make HTTP client usable.  We need to make 2 attempts in
	// the case when the connection was closed (due to inactivity for example)
	// AND the server refuses to open a 0-RTT connection.
	for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
		client, err = p.resetClient(err)
		if err != nil {
			return nil, fmt.Errorf("failed to reset http client: %w", err)
		}

		resp, err = p.exchangeHTTPS(client, req)
	}

	if err != nil {
		// If the request failed anyway, make sure we don't use this client.
		_, resErr := p.resetClient(err)

		return nil, errors.WithDeferred(err, resErr)
	}

	return resp, err
}

// Close implements the Upstream interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Close() (err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	runtime.SetFinalizer(p, nil)

	if p.client != nil {
		err = p.closeClient(p.client)
	}

	return err
}

// closeClient cleans up resources used by client if necessary.  Note that this
// should be done for HTTP/3, as it can lead to resource leaks due to keep-alive
// connections, and for HTTP/2 due to idle connections.
func (p *dnsOverHTTPS) closeClient(client *http.Client) (err error) {
	if isHTTP3(client) {
		return client.Transport.(io.Closer).Close()
	} else if p.transportH2 != nil {
		p.transportH2.CloseIdleConnections()
	}

	return nil
}

// exchangeHTTPS logs the request and its result and calls exchangeHTTPSClient.
func (p *dnsOverHTTPS) exchangeHTTPS(client *http.Client, req *dns.Msg) (resp *dns.Msg, err error) {
	n := networkTCP
	if isHTTP3(client) {
		n = networkUDP
	}

	logBegin(p.logger, p.addrRedacted, n, req)
	defer func() { logFinish(p.logger, p.addrRedacted, n, err) }()

	return p.exchangeHTTPSClient(client, req)
}

// exchangeHTTPSClient sends the DNS query to a DoH resolver using the specified
// http.Client instance.
func (p *dnsOverHTTPS) exchangeHTTPSClient(
	client *http.Client,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet
	if isHTTP3(client) {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}

	u := url.URL{
		Scheme:   p.addr.Scheme,
		User:     p.addr.User,
		Host:     p.addr.Host,
		Path:     p.addr.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.addrRedacted, err)
	}

	// Prevent the client from sending User-Agent header, see
	// https://github.com/AdguardTeam/dnsproxy/issues/211.
	httpReq.Header.Set(httphdr.UserAgent, "")
	httpReq.Header.Set(httphdr.Accept, "application/dns-message")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", p.addrRedacted, err)
	}
	defer slogutil.CloseAndLog(httpReq.Context(), p.logger, httpResp.Body, slog.LevelDebug)

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.addrRedacted, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"expected status %d, got %d from %s",
			http.StatusOK,
			httpResp.StatusCode,
			p.addrRedacted,
		)
	}

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			p.addrRedacted,
			body,
			err,
		)
	}

	if resp.Id != req.Id {
		err = dns.ErrId
	}

	return resp, err
}

// shouldRetry checks what error we have received and returns true if we should
// re-create the HTTP client and retry the request.
func (p *dnsOverHTTPS) shouldRetry(err error) (ok bool) {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// If this is a timeout error, trying to forcibly re-create the HTTP
		// client instance.  This is an attempt to fix an issue with DoH client
		// stalling after a network change.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/3217.
		return true
	}

	if isQUICRetryError(err) {
		return true
	}

	return false
}

// resetClient triggers re-creation of the *http.Client that is used by this
// upstream.  This method accepts the error that caused resetting client as
// depending on the error we may also reset the QUIC config.
func (p *dnsOverHTTPS) resetClient(resetErr error) (client *http.Client, err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	if errors.Is(resetErr, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		p.resetQUICConfig()
	}

	oldClient := p.client
	if oldClient != nil {
		closeErr := p.closeClient(oldClient)
		if closeErr != nil {
			p.logger.Warn("failed to close the old http client", slogutil.KeyError, closeErr)
		}
	}

	p.logger.Debug("recreating the http client", slogutil.KeyError, resetErr)
	p.client, err = p.createClient()

	return p.client, err
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (p *dnsOverHTTPS) getQUICConfig() (c *quic.Config) {
	p.quicConfMu.Lock()
	defer p.quicConfMu.Unlock()

	return p.quicConf
}

// resetQUICConfig Re-create the token store to make sure we're not trying to
// use invalid for 0-RTT.
func (p *dnsOverHTTPS) resetQUICConfig() {
	p.quicConfMu.Lock()
	defer p.quicConfMu.Unlock()

	p.quicConf = p.quicConf.Clone()
	p.quicConf.TokenStore = newQUICTokenStore()
}

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DoH resolver.
func (p *dnsOverHTTPS) getClient() (c *http.Client, isCached bool, err error) {
	startTime := time.Now()

	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	if p.client != nil {
		return p.client, true, nil
	}

	// Timeout can be exceeded while waiting for the lock. This happens quite
	// often on mobile devices.
	elapsed := time.Since(startTime)
	if p.timeout > 0 && elapsed > p.timeout {
		return nil, false, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	p.logger.Debug("creating a new http client")
	p.client, err = p.createClient()

	return p.client, false, err
}

// createClient creates a new *http.Client instance.  The HTTP protocol version
// will depend on whether HTTP3 is allowed and provided by this upstream.  Note,
// that we'll attempt to establish a QUIC connection when creating the client in
// order to check whether HTTP3 is supported.
func (p *dnsOverHTTPS) createClient() (*http.Client, error) {
	transport, err := p.createTransport()
	if err != nil {
		return nil, fmt.Errorf("initializing http transport: %w", err)
	}

	client := &http.Client{
		Transport: transport,
		// TODO(ameshkov):  p.timeout may appear zero that will disable the
		// timeout for client, consider using the default.
		Timeout: p.timeout,
		Jar:     nil,
	}

	p.client = client

	return p.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically
// for this DoH resolver.  This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver. Note,
// that this function will first attempt to establish a QUIC connection (if
// HTTP3 is enabled in the upstream options).  If this attempt is successful,
// it returns an HTTP3 transport, otherwise it returns the H1/H2 transport.
func (p *dnsOverHTTPS) createTransport() (t http.RoundTripper, err error) {
	tlsConf := p.tlsConf.Clone()

	if p.proxy != nil {
		// A proxied request needs no bootstrap at all: [http.Transport] dials
		// the proxy, and the proxy resolves this upstream's hostname itself.
		// So the bootstrap is deferred to the dial handler, which needs it only
		// if a request turns out to be sent directly.  Otherwise a network that
		// permits no plain DNS, which is the very reason to use a proxy, could
		// not bring this upstream up at all.
		//
		// Note that HTTP/3 cannot be reached from here, since [newDoH] rejects
		// a proxy combined with it.
		return p.newTransportH1H2(tlsConf, p.proxyDialContext())
	}

	dialContext, err := p.getDialer()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.addrRedacted, err)
	}

	// First, we attempt to create an HTTP3 transport.  If the probe QUIC
	// connection is established successfully, we'll be using HTTP3 for this
	// upstream.
	transportH3, err := p.createTransportH3(tlsConf, dialContext)
	if err == nil {
		p.logger.Debug("using http/3 for this upstream, quic was faster")

		return transportH3, nil
	}

	p.logger.Debug("got error, switching to http/2 for this upstream", slogutil.KeyError, err)

	return p.newTransportH1H2(tlsConf, dialContext)
}

// newTransportH1H2 returns an HTTP/1.1 and HTTP/2 transport for this upstream
// that dials with dialContext.  Note that it also sets p.transportH2, so that
// the HTTP/2 transport can be configured after the fact.
func (p *dnsOverHTTPS) newTransportH1H2(
	tlsConf *tls.Config,
	dialContext bootstrap.DialHandler,
) (t http.RoundTripper, err error) {
	if !p.supportsHTTP() {
		return nil, errors.Error("HTTP1/1 and HTTP2 are not supported by this upstream")
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConf,
		Proxy:              p.proxy,
		DisableCompression: true,
		DialContext:        dialContext,
		IdleConnTimeout:    transportDefaultIdleConnTimeout,
		MaxConnsPerHost:    dohMaxConnsPerHost,
		MaxIdleConns:       dohMaxIdleConns,
		// Since we have a custom DialContext, we need to use this field to make
		// golang http.Client attempt to use HTTP/2. Otherwise, it would only be
		// used when negotiated on the TLS level.
		ForceAttemptHTTP2: true,
	}

	// Explicitly configure transport to use HTTP/2.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/11.
	p.transportH2, err = http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	// Enable HTTP/2 pings on idle connections.
	p.transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout

	return transport, nil
}

// checkProxyScheme wraps proxy to reject the URL schemes that [http.Transport]
// would connect to using this upstream's own TLS configuration.  That
// configuration pins the upstream's server name, root pool, and client
// certificate, none of which apply to a proxy, so an "https" proxy would fail
// its certificate verification and be offered the upstream's client
// certificate.  An empty scheme is accepted since the transport treats it as
// "http"; the Windows PAC resolution produces such URLs.
//
// It is applied here, per returned URL, rather than at construction, since a
// proxy func may return a different URL for every request.
func checkProxyScheme(proxy ProxyFunc) (checked ProxyFunc) {
	if proxy == nil {
		return nil
	}

	return func(req *http.Request) (proxyURL *url.URL, err error) {
		proxyURL, err = proxy(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err
		}

		switch proxyURL.Scheme {
		case "", "http", "socks5", "socks5h":
			return proxyURL, nil
		default:
			return nil, fmt.Errorf("proxy scheme %q is not supported", proxyURL.Scheme)
		}
	}
}

// proxyDialContext returns the dial handler for an upstream that has a proxy
// configured.  The bootstrap dials the bootstrapped addresses of this upstream
// regardless of the address it is asked for, which is wrong once a proxy is in
// play: [http.Transport] asks for the proxy's address, not the upstream's.  So
// anything but the upstream's own address is dialed as given.
//
// The bootstrap is initialized here rather than by the caller, so that it only
// runs if the upstream's own address is dialed, that is, if [Options.Proxy]
// returned no proxy for a request.
//
// Note that a proxy hostname is resolved by the system resolver, since the
// bootstrap of this upstream only knows how to reach the upstream.
func (p *dnsOverHTTPS) proxyDialContext() (h bootstrap.DialHandler) {
	upsAddr := transportAddr(p.addr)
	dialer := &net.Dialer{
		Timeout: p.timeout,
	}

	return func(
		ctx context.Context,
		network bootstrap.Network,
		addr string,
	) (conn net.Conn, err error) {
		if !strings.EqualFold(addr, upsAddr) {
			p.logger.DebugContext(ctx, "dialing proxy", "addr", addr)

			return dialer.DialContext(ctx, network, addr)
		}

		// Note that the bootstrap runs on its own context with the upstream
		// timeout, see [bootstrap.ResolveDialContext], so ctx does not cancel
		// it.  A stalled bootstrap therefore holds this dial for up to that
		// timeout even if the request is already gone.
		boot, err := p.getDialer()
		if err != nil {
			return nil, fmt.Errorf("bootstrapping %s: %w", p.addrRedacted, err)
		}

		return boot(ctx, network, addr)
	}
}

// transportAddr returns the host:port of u the way [http.Transport] derives the
// address it dials, so that the two can be compared.  Note that u always has a
// port here, since [addPort] has run on it.
func transportAddr(u *url.URL) (addr string) {
	host := u.Hostname()

	// Convert to punycode as [http.Transport] does, so that an
	// internationalized domain name still matches.  A host that cannot be
	// converted is compared as is: the worst case is that it never matches,
	// and the upstream is dialed directly instead of through its bootstrap.
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = ascii
	}

	return net.JoinHostPort(host, u.Port())
}

// http3Transport is a wrapper over [*http3.Transport] that tries to optimize
// its behavior.  The main thing that it does is trying to force use a single
// connection to a host instead of creating a new one all the time.  It also
// helps mitigate race issues with quic-go.
type http3Transport struct {
	baseTransport *http3.Transport

	closed bool
	mu     sync.RWMutex
}

// type check
var _ http.RoundTripper = (*http3Transport)(nil)

// RoundTrip implements the http.RoundTripper interface for *http3Transport.
func (h *http3Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, net.ErrClosed
	}

	// Try to use cached connection to the target host if it's available.
	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})

	if errors.Is(err, http3.ErrNoCachedConn) {
		// If there are no cached connection, trigger creating a new one.
		resp, err = h.baseTransport.RoundTrip(req)
	}

	return resp, err
}

// type check
var _ io.Closer = (*http3Transport)(nil)

// Close implements the io.Closer interface for *http3Transport.
func (h *http3Transport) Close() (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true

	return h.baseTransport.Close()
}

// createTransportH3 tries to create an HTTP/3 transport for this upstream.  We
// should be able to fall back to H1/H2 in case if HTTP/3 is unavailable or if
// it is too slow.  In order to do that, this method will run two probes in
// parallel (one for TLS, the other one for QUIC) and if QUIC is faster it will
// create the [*http3.Transport] instance.
func (p *dnsOverHTTPS) createTransportH3(
	tlsConfig *tls.Config,
	dialContext bootstrap.DialHandler,
) (roundTripper http.RoundTripper, err error) {
	if !p.supportsH3() {
		return nil, errors.Error("HTTP3 support is not enabled")
	}

	addr, err := p.probeH3(tlsConfig, dialContext)
	if err != nil {
		return nil, err
	}

	rt := &http3.Transport{
		Dial: func(
			ctx context.Context,

			// Ignore the address and always connect to the one that we got
			// from the bootstrapper.
			_ string,
			tlsCfg *tls.Config,
			cfg *quic.Config,
		) (c quic.EarlyConnection, err error) {
			c, err = quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
			return c, err
		},
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		QUICConfig:         p.getQUICConfig(),
	}

	return &http3Transport{baseTransport: rt}, nil
}

// probeH3 runs a test to check whether QUIC is faster than TLS for this
// upstream.  If the test is successful it will return the address that we
// should use to establish the QUIC connections.
func (p *dnsOverHTTPS) probeH3(
	tlsConfig *tls.Config,
	dialContext bootstrap.DialHandler,
) (addr string, err error) {
	// We're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there are v4/v6 addresses).
	rawConn, err := dialContext(context.Background(), "udp", "")
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	// It's never actually used.
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return "", fmt.Errorf("not a UDP connection to %s", p.addrRedacted)
	}

	addr = udpConn.RemoteAddr().String()

	// Avoid spending time on probing if this upstream only supports HTTP/3.
	if p.supportsH3() && !p.supportsHTTP() {
		return addr, nil
	}

	// Use a new *tls.Config with empty session cache for probe connections.
	// Surprisingly, this is really important since otherwise it invalidates
	// the existing cache.
	// TODO(ameshkov): figure out why the sessions cache invalidates here.
	probeTLSCfg := tlsConfig.Clone()
	probeTLSCfg.ClientSessionCache = nil

	// Do not expose probe connections to the callbacks that are passed to
	// the bootstrap options to avoid side-effects.
	// TODO(ameshkov): consider exposing, somehow mark that this is a probe.
	probeTLSCfg.VerifyPeerCertificate = nil
	probeTLSCfg.VerifyConnection = nil

	// Run probeQUIC and probeTLS in parallel and see which one is faster.
	chQUIC := make(chan error, 1)
	chTLS := make(chan error, 1)
	go p.probeQUIC(addr, probeTLSCfg, chQUIC)
	go p.probeTLS(dialContext, probeTLSCfg, chTLS)

	select {
	case quicErr := <-chQUIC:
		if quicErr != nil {
			// QUIC failed, return error since HTTP3 was not preferred.
			return "", quicErr
		}

		// Return immediately, QUIC was faster.
		return addr, quicErr
	case tlsErr := <-chTLS:
		if tlsErr != nil {
			// Return immediately, TLS failed.
			p.logger.Debug("probing tls", slogutil.KeyError, tlsErr)

			return addr, nil
		}

		return "", errors.Error("TLS was faster than QUIC, prefer it")
	}
}

// probeQUIC attempts to establish a QUIC connection to the specified address.
// We run probeQUIC and probeTLS in parallel and see which one is faster.
func (p *dnsOverHTTPS) probeQUIC(addr string, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	t := p.timeout
	if t == 0 {
		t = dialTimeout
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(t))
	defer cancel()

	conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, p.getQUICConfig())
	if err != nil {
		ch <- fmt.Errorf("opening quic connection to %s: %w", p.addrRedacted, err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.CloseWithError(QUICCodeNoError, "")

	ch <- nil

	elapsed := time.Since(startTime)
	p.logger.Debug("quic connection established", "elapsed", elapsed)
}

// probeTLS attempts to establish a TLS connection to the specified address. We
// run probeQUIC and probeTLS in parallel and see which one is faster.
func (p *dnsOverHTTPS) probeTLS(dialContext bootstrap.DialHandler, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	conn, err := tlsDial(dialContext, tlsConfig)
	if err != nil {
		ch <- fmt.Errorf("opening TLS connection: %w", err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.Close()

	ch <- nil

	elapsed := time.Since(startTime)
	p.logger.Debug("tls connection established", "elapsed", elapsed)
}

// supportsH3 returns true if HTTP/3 is supported by this upstream.
func (p *dnsOverHTTPS) supportsH3() (ok bool) {
	for _, v := range p.tlsConf.NextProtos {
		if v == string(HTTPVersion3) {
			return true
		}
	}

	return false
}

// supportsHTTP returns true if HTTP/1.1 or HTTP2 is supported by this upstream.
func (p *dnsOverHTTPS) supportsHTTP() (ok bool) {
	for _, v := range p.tlsConf.NextProtos {
		if v == string(HTTPVersion11) || v == string(HTTPVersion2) {
			return true
		}
	}

	return false
}

// isHTTP3 checks if the *http.Client is an HTTP/3 client.
func isHTTP3(client *http.Client) (ok bool) {
	_, ok = client.Transport.(*http3Transport)

	return ok
}
