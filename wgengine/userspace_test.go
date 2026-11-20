// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"go4.org/mem"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/control/controlknobs"
	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestPeerWireGuardStateValuesMatchWireguardGo(t *testing.T) {
	const unknownPeerSessionState device.PeerSessionState = 255

	tests := []struct {
		name string
		wg   device.PeerSessionState
		want PeerWireGuardState
	}{
		{"none", device.PeerSessionNone, PeerWireGuardStateNone},
		{"handshake", device.PeerSessionHandshake, PeerWireGuardStateHandshake},
		{"established", device.PeerSessionEstablished, PeerWireGuardStateEstablished},
		{"expired", device.PeerSessionExpired, PeerWireGuardStateExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerWireGuardStateFromDevice(tt.wg); got != tt.want {
				t.Fatalf("converted state = %v; want %v", got, tt.want)
			}
			if got, want := uint8(tt.wg), uint8(tt.want); got != want {
				t.Fatalf("wireguard-go const = %v; want %v", got, want)
			}
		})
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unknown wireguard-go state")
		}
	}()
	_ = peerWireGuardStateFromDevice(unknownPeerSessionState)
}

func nodeViews(v []*tailcfg.Node) []tailcfg.NodeView {
	nv := make([]tailcfg.NodeView, len(v))
	for i, n := range v {
		nv[i] = n.View()
	}
	return nv
}

func TestUserspaceEngineReconfig(t *testing.T) {
	bus := eventbustest.NewBus(t)

	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	routerCfg := &router.Config{}

	for i, nodeHex := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		nm := &netmap.NetworkMap{
			Peers: nodeViews([]*tailcfg.Node{
				{
					ID:  1,
					Key: nkFromHex(nodeHex),
				},
			}),
		}
		cfg := &wgcfg.Config{
			Addresses: []netip.Prefix{
				netip.PrefixFrom(netaddr.IPv4(100, 100, 99, byte(1+i)), 32),
			},
		}

		e.SetSelfNode(nm.SelfNode)
		err = e.Reconfig(cfg, routerCfg, &dns.Config{})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// failingRouter is a router.Router whose Set always fails, used to verify that
// DNS configuration is still attempted when router configuration fails.
type failingRouter struct {
	err error
}

func (failingRouter) Up() error                  { return nil }
func (r failingRouter) Set(*router.Config) error { return r.err }
func (failingRouter) Close() error               { return nil }

// closeCountingRouter is a failingRouter that counts its Close calls.
type closeCountingRouter struct {
	failingRouter
	closeErr error
	closed   atomic.Int32
}

func (r *closeCountingRouter) Close() error {
	r.closed.Add(1)
	return r.closeErr
}

// closeCountingTUN counts the Close calls of the device it wraps.
type closeCountingTUN struct {
	tun.Device
	closeErr error
	closed   atomic.Int32
}

func (d *closeCountingTUN) Close() error {
	d.closed.Add(1)
	return errors.Join(d.Device.Close(), d.closeErr)
}

// TestNewUserspaceEngineErrorCleanup checks that a constructor that fails
// after binding its sockets releases its UDP port, closes its resources
// once each and reports their errors in cleanup order.
func TestNewUserspaceEngineErrorCleanup(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_ALWAYS_USE_DERP", "false")
	bus := eventbustest.NewBus(t)
	watcher := eventbustest.NewWatcher(t, bus)

	bird := new(closeCountingBird)
	defer HookNewBird.SetForTest(func(logger.Logf, string) (Bird, error) { return bird, nil })()
	osCfg := new(closeCountingOSConfigurator)
	setErr := errors.New("router Set failed")
	closeErr := errors.New("router Close failed")
	tunErr := errors.New("TUN Close failed")
	dev := &closeCountingTUN{Device: tuntest.NewChannelTUN().TUN(), closeErr: tunErr}
	rtr := &closeCountingRouter{failingRouter: failingRouter{setErr}, closeErr: closeErr}
	_, err := NewUserspaceEngine(t.Logf, Config{
		Tun:           dev,
		Router:        rtr,
		DNS:           osCfg,
		BIRDSocket:    "bird.ctl",
		HealthTracker: health.NewTracker(bus),
		Metrics:       new(usermetric.Registry),
		EventBus:      bus,
	})
	want := []error{setErr, closeErr, tunErr}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) != len(want) {
		t.Fatalf("NewUserspaceEngine error = %v, want causes %v", err, want)
	}
	for i, cause := range want {
		if !errors.Is(err, cause) || !errors.Is(joined.Unwrap()[i], cause) {
			t.Errorf("NewUserspaceEngine error = %v, want cause %d to match %v", err, i, cause)
		}
	}
	if n := dev.closed.Load(); n != 1 {
		t.Errorf("device closed %d times, want 1", n)
	}
	if n := rtr.closed.Load(); n != 1 {
		t.Errorf("router closed %d times, want 1", n)
	}
	if n, want := osCfg.closed.Load(), closes(buildfeatures.HasDNS); n != want {
		t.Errorf("DNS configurator closed %d times, want %d", n, want)
	}
	if n, want := bird.closed.Load(), closes(buildfeatures.HasBird); n != want {
		t.Errorf("BIRD client closed %d times, want %d", n, want)
	}
	if !buildfeatures.HasUDPTransport || runtime.GOOS == "js" {
		return
	}
	var port uint16
	if err := eventbustest.Expect(watcher, func(p router.PortUpdate) bool {
		if p.EndpointNetwork != "udp4" {
			return false
		}
		port = p.UDPPort
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if port == 0 {
		t.Fatal("magicsock reported UDP4 port zero")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil {
		t.Fatalf("UDP port %d still bound: %v", port, err)
	}
	c.Close()
}

func TestCloseOnErrorPoolPreservesStartupError(t *testing.T) {
	startup := errors.New("startup failed")
	err := startup
	var pool closeOnErrorPool
	pool.add(func() error { return nil })
	pool.closeAllIfError(&err)
	if err != startup {
		t.Errorf("successful cleanup replaced the startup error with %v", err)
	}
}

// closes returns the number of closes expected of a backend that is
// compiled in when has is true.
func closes(has bool) int32 {
	if has {
		return 1
	}
	return 0
}

// closeCountingOSConfigurator is a dns.OSConfigurator that counts its Close
// calls.
type closeCountingOSConfigurator struct {
	recordingOSConfigurator
	closed atomic.Int32
}

func (c *closeCountingOSConfigurator) Close() error { c.closed.Add(1); return nil }

// closeCountingBird is a Bird that counts its Close calls.
type closeCountingBird struct {
	closed atomic.Int32
}

func (*closeCountingBird) Reconfig(tailcfg.NodeView) bool { return false }
func (*closeCountingBird) ReconfigDone()                  {}
func (b *closeCountingBird) Close()                       { b.closed.Add(1) }

// recordingOSConfigurator is a dns.OSConfigurator that records whether SetDNS
// was called.
type recordingOSConfigurator struct {
	setDNSCalled bool
}

func (c *recordingOSConfigurator) SetDNS(dns.OSConfig) error { c.setDNSCalled = true; return nil }
func (c *recordingOSConfigurator) SupportsSplitDNS() bool    { return false }
func (c *recordingOSConfigurator) Close() error              { return nil }
func (c *recordingOSConfigurator) GetBaseConfig() (dns.OSConfig, error) {
	return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
}

// TestUserspaceEngineReconfigDNSAfterRouterError verifies that a router.Set
// failure does not prevent DNS from being configured. Historically Reconfig
// returned on router error before dns.Set ran, so MagicDNS was never
// configured on hosts where router config failed on every reconfig. See
// tailscale/tailscale#20447.
func TestUserspaceEngineReconfigDNSAfterRouterError(t *testing.T) {
	bus := eventbustest.NewBus(t)

	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	ue := e.(*userspaceEngine)

	routerErr := fmt.Errorf("router boom")
	ue.router = failingRouter{err: routerErr}

	osCfg := &recordingOSConfigurator{}
	ue.dns = dns.NewManager(t.Logf, osCfg, ht, ue.dialer, nil, nil, runtime.GOOS, bus, nil)

	nm := &netmap.NetworkMap{
		Peers: nodeViews([]*tailcfg.Node{{ID: 1, Key: nkFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")}}),
	}
	cfg := &wgcfg.Config{
		Addresses: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 100, 99, 1), 32)},
	}
	e.SetSelfNode(nm.SelfNode)

	err = e.Reconfig(cfg, &router.Config{}, &dns.Config{})

	if !osCfg.setDNSCalled {
		t.Error("SetDNS was not called after router.Set failed; DNS config must be independent of router success")
	}
	if err == nil {
		t.Error("Reconfig returned nil; want the router error to be surfaced")
	} else if !errors.Is(err, routerErr) {
		t.Errorf("Reconfig error = %v; want it to wrap the router error %v", err, routerErr)
	}
}

func TestUserspaceEnginePortReconfig(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/2855")
	const defaultPort = 49983

	var knobs controlknobs.Knobs

	bus := eventbustest.NewBus(t)

	// Keep making a wgengine until we find an unused port
	var ue *userspaceEngine
	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	for range 100 {
		attempt := uint16(defaultPort + rand.Intn(1000))
		e, err := NewFakeUserspaceEngine(t.Logf, attempt, &knobs, ht, reg, bus)
		if err != nil {
			t.Fatal(err)
		}
		ue = e.(*userspaceEngine)
		if ue.magicConn.LocalPort() == attempt {
			break
		}
		ue.Close()
		ue = nil
	}
	if ue == nil {
		t.Fatal("could not create a wgengine with a specific port")
	}
	t.Cleanup(ue.Close)

	startingPort := ue.magicConn.LocalPort()
	cfg := &wgcfg.Config{
		Addresses: []netip.Prefix{
			netip.PrefixFrom(netaddr.IPv4(100, 100, 99, 1), 32),
		},
	}
	routerCfg := &router.Config{}
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if got := ue.magicConn.LocalPort(); got != startingPort {
		t.Errorf("no debug setting changed local port to %d from %d", got, startingPort)
	}

	knobs.RandomizeClientPort.Store(true)
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if got := ue.magicConn.LocalPort(); got == startingPort {
		t.Errorf("debug setting did not change local port from %d", startingPort)
	}

	lastPort := ue.magicConn.LocalPort()
	knobs.RandomizeClientPort.Store(false)
	if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if startingPort == defaultPort {
		// Only try this if we managed to bind defaultPort the first time.
		// Otherwise, assume someone else on the computer is using defaultPort
		// and so Reconfig would have caused magicSockt to bind some other port.
		if got := ue.magicConn.LocalPort(); got != defaultPort {
			t.Errorf("debug setting did not change local port from %d to %d", startingPort, defaultPort)
		}
	}
	if got := ue.magicConn.LocalPort(); got == lastPort {
		t.Errorf("Reconfig did not change local port from %d", lastPort)
	}
}

// Test that enabling and disabling peer path MTU discovery works correctly.
func TestUserspaceEnginePeerMTUReconfig(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; peer MTU not supported", runtime.GOOS)
	}

	envknob.SetenvForTest(t, "TS_DEBUG_ENABLE_PMTUD", "")
	// Turn on debugging to help diagnose problems.
	envknob.SetenvForTest(t, "TS_DEBUG_PMTUD", "true")

	var knobs controlknobs.Knobs

	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, &knobs, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	ue := e.(*userspaceEngine)

	if ue.magicConn.PeerMTUEnabled() != false {
		t.Error("peer MTU enabled by default, should not be")
	}
	osDefaultDF, err := ue.magicConn.DontFragSetting()
	if err != nil {
		t.Errorf("get don't fragment bit failed: %v", err)
	}
	t.Logf("Info: OS default don't fragment bit(s) setting: %v", osDefaultDF)

	// Build a set of configs to use as we change the peer MTU settings.
	cfg := &wgcfg.Config{
		Addresses: []netip.Prefix{
			netip.PrefixFrom(netaddr.IPv4(100, 100, 99, 1), 32),
		},
	}
	routerCfg := &router.Config{}

	tests := []struct {
		desc    string   // test description
		wantP   bool     // desired value of PMTUD setting
		wantDF  bool     // desired value of don't fragment bits
		shouldP opt.Bool // if set, force peer MTU to this value
	}{
		{desc: "after_first_reconfig", wantP: false, wantDF: osDefaultDF, shouldP: ""},
		{desc: "enabling_PMTUD_first_time", wantP: true, wantDF: true, shouldP: "true"},
		{desc: "disabling_PMTUD", wantP: false, wantDF: false, shouldP: "false"},
		{desc: "enabling_PMTUD_second_time", wantP: true, wantDF: true, shouldP: "true"},
		{desc: "returning_to_default_PMTUD", wantP: false, wantDF: false, shouldP: ""},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if v, ok := tt.shouldP.Get(); ok {
				knobs.PeerMTUEnable.Store(v)
			} else {
				knobs.PeerMTUEnable.Store(false)
			}
			if err := ue.Reconfig(cfg, routerCfg, &dns.Config{}); err != nil {
				t.Fatal(err)
			}
			if v := ue.magicConn.PeerMTUEnabled(); v != tt.wantP {
				t.Errorf("peer MTU set to %v, want %v", v, tt.wantP)
			}
			if v, err := ue.magicConn.DontFragSetting(); v != tt.wantDF || err != nil {
				t.Errorf("don't fragment bit set to %v, want %v, err %v", v, tt.wantP, err)
			}
		})
	}
}

func nkFromHex(hex string) key.NodePublic {
	if len(hex) != 64 {
		panic(fmt.Sprintf("%q is len %d; want 64", hex, len(hex)))
	}
	k, err := key.ParseNodePublicUntyped(mem.S(hex[:64]))
	if err != nil {
		panic(fmt.Sprintf("%q is not hex: %v", hex, err))
	}
	return k
}

// an experiment to see if genLocalAddrFunc was worth it. As of Go
// 1.16, it still very much is. (30-40x faster)
func BenchmarkGenLocalAddrFunc(b *testing.B) {
	la1 := netip.MustParseAddr("1.2.3.4")
	la2 := netip.MustParseAddr("::4")
	lanot := netip.MustParseAddr("5.5.5.5")
	var x bool
	b.Run("map1", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		m := map[netip.Addr]bool{
			la1: true,
		}
		for range b.N {
			x = m[la1]
			x = m[lanot]
		}
	})
	b.Run("map2", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		m := map[netip.Addr]bool{
			la1: true,
			la2: true,
		}
		for range b.N {
			x = m[la1]
			x = m[lanot]
		}
	})
	b.Run("or1", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		f := func(t netip.Addr) bool {
			return t == la1
		}
		for range b.N {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Run("or2", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		f := func(t netip.Addr) bool {
			return t == la1 || t == la2
		}
		for range b.N {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Logf("x = %v", x)
}

// Regression test for #19730: on major link change, MatchDomains Routes must
// be preserved.
func TestLinkChangeReapplyPreservesMagicDNSRoutes(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "android", "darwin", "ios", "openbsd":
	default:
		t.Skipf("linkChange DNS reapply path not exercised on %s", runtime.GOOS)
	}

	bus := eventbustest.NewBus(t)
	noop, err := dns.NewNoopManager()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewUserspaceEngine(t.Logf, Config{
		HealthTracker:   health.NewTracker(bus),
		Metrics:         new(usermetric.Registry),
		EventBus:        bus,
		DNS:             noop,
		DNSServiceAddrs: []netip.Addr{netip.MustParseAddr("100.100.100.100")},
		RespondToPing:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	var (
		mu   sync.Mutex
		last resolver.Config
	)
	e.(*userspaceEngine).dns.Resolver().TestOnlySetHook(func(cfg resolver.Config) {
		mu.Lock()
		defer mu.Unlock()
		last = cfg
	})
	snapshot := func() []dnsname.FQDN {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(last.LocalDomains)
	}

	dnsCfg := &dns.Config{
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			"ts.net.":              {{Addr: "199.247.155.53"}},
			"foo.ts.net.":          nil,
			"64.100.in-addr.arpa.": nil,
		},
		Hosts: map[dnsname.FQDN][]netip.Addr{
			"node.foo.ts.net.": {netip.MustParseAddr("100.64.0.5")},
		},
		SearchDomains: []dnsname.FQDN{"foo.ts.net."},
	}
	if err := e.Reconfig(&wgcfg.Config{}, &router.Config{}, dnsCfg); err != nil {
		t.Fatalf("Reconfig: %v", err)
	}
	initial := snapshot()

	cd, err := netmon.NewChangeDelta(nil, &netmon.State{HaveV4: true}, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	cd.RebindLikelyRequired = true
	e.(*userspaceEngine).linkChange(cd)

	after := snapshot()
	slices.Sort(initial)
	slices.Sort(after)
	if !slices.Equal(initial, after) {
		t.Errorf("resolver LocalDomains changed after linkChange:\n  initial: %s\n  after:   %s",
			logger.AsJSON(initial), logger.AsJSON(after))
	}
}

// TestCloseWaitsForLinkChange tests that Close waits for in-flight
// linkChangeQueue work to finish before tearing down the subsystems
// that linkChange uses.
//
// See https://github.com/tailscale/tailscale/issues/17641.
func TestCloseWaitsForLinkChange(t *testing.T) {
	bus := eventbustest.NewBus(t)

	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	e.(*userspaceEngine).linkChangeQueue.Add(func() {
		close(started)
		<-release
		close(done)
	})
	<-started

	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	e.Close()
	select {
	case <-done:
	default:
		t.Fatal("Close returned with link change work still in flight")
	}
}

// TestDERPAppNamePlumbing tests that Config.DERPAppName makes it all
// the way from the engine config to the ClientInfo received by an
// in-process DERP server.
func TestDERPAppNamePlumbing(t *testing.T) {
	const appName = "app-name-plumbing-test"

	priv := key.NewNode()
	infoCh := make(chan derp.ClientInfo, 1)

	derpSrv := derpserver.New(key.NewNode(), t.Logf)
	derpSrv.ForTest().SetOnClientInfo(func(k key.NodePublic, info derp.ClientInfo) {
		if k != priv.Public() {
			return
		}
		select {
		case infoCh <- info:
		default:
		}
	})
	httpsrv := httptest.NewUnstartedServer(derpserver.Handler(derpSrv))
	httpsrv.Config.ErrorLog = logger.StdLogger(t.Logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		derpSrv.Close()
	})

	stunAddr, stunCleanup := stuntest.Serve(t)
	t.Cleanup(stunCleanup)

	derpMap := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{{
					Name:             "t1",
					RegionID:         1,
					HostName:         "test-node.unused",
					IPv4:             "127.0.0.1",
					IPv6:             "none",
					STUNPort:         stunAddr.Port,
					DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
					InsecureForTests: true,
				}},
			},
		},
	}

	bus := eventbustest.NewBus(t)
	noopDNS, err := dns.NewNoopManager()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewUserspaceEngine(t.Logf, Config{
		HealthTracker: health.NewTracker(bus),
		Metrics:       new(usermetric.Registry),
		EventBus:      bus,
		DNS:           noopDNS,
		DERPAppName:   appName,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	if err := e.Reconfig(&wgcfg.Config{PrivateKey: priv}, &router.Config{}, &dns.Config{}); err != nil {
		t.Fatalf("Reconfig: %v", err)
	}
	e.(*userspaceEngine).magicConn.SetDERPMap(derpMap)

	select {
	case info := <-infoCh:
		if info.AppName != appName {
			t.Fatalf("ClientInfo.AppName = %q; want %q", info.AppName, appName)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for engine to connect to the test DERP server")
	}
}
