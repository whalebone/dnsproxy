package dnsproxytest_test

import (
	"github.com/whalebone/dnsproxy/internal/dnsmsg"
	"github.com/whalebone/dnsproxy/internal/dnsproxytest"
	"github.com/whalebone/dnsproxy/upstream"
)

// type checks
var (
	_ upstream.Upstream         = (*dnsproxytest.FakeUpstream)(nil)
	_ dnsmsg.MessageConstructor = (*dnsproxytest.TestMessageConstructor)(nil)
)
