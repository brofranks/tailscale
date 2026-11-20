// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
)

func TestGetInterfaceIndex(t *testing.T) {
	oldVal := bindToInterfaceByRoute.Load()
	t.Cleanup(func() { bindToInterfaceByRoute.Store(oldVal) })
	bindToInterfaceByRoute.Store(true)

	tests := []struct {
		name string
		addr string
		err  string
	}{
		{
			name: "IP_and_port",
			addr: "8.8.8.8:53",
		},
		{
			name: "bare_ip",
			addr: "8.8.8.8",
		},
		{
			name: "invalid",
			addr: "!!!!!",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := getInterfaceIndex(t.Logf, nil, tc.addr)
			if err != nil {
				if tc.err == "" {
					t.Fatalf("got unexpected error: %v", err)
				}
				if errstr := err.Error(); errstr != tc.err {
					t.Errorf("expected error %q, got %q", errstr, tc.err)
				}
			} else {
				t.Logf("getInterfaceIndex(%q) = %d", tc.addr, idx)
				if tc.err != "" {
					t.Fatalf("wanted error %q", tc.err)
				}
				if idx < 0 {
					t.Fatalf("got invalid index %d", idx)
				}
			}
		})
	}

	t.Run("NoTailscale", func(t *testing.T) {
		name, _ := netmon.TailscaleInterfaceName()
		tsif, err := tailscaleInterface(name)
		if err != nil {
			t.Fatal(err)
		}
		if tsif == nil {
			t.Skip("no tailscale interface on this machine")
		}

		defaultIdx, err := netmon.DefaultRouteInterfaceIndex()
		if err != nil {
			t.Fatal(err)
		}

		idx, err := getInterfaceIndex(t.Logf, nil, "100.100.100.100:53")
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tailscaleIdx=%d defaultIdx=%d idx=%d", tsif.Index, defaultIdx, idx)

		if idx == tsif.Index {
			t.Fatalf("got idx=%d; wanted not Tailscale interface", idx)
		} else if idx != defaultIdx {
			t.Fatalf("got idx=%d, want %d", idx, defaultIdx)
		}
	})
}

func TestMissingRegisteredTunnel(t *testing.T) {
	tstest.Replace(t, &guessTailscaleInterface, func() (*net.Interface, error) {
		t.Fatal("scanned for another utun after the registered device disappeared")
		return nil, nil
	})
	if got, err := tailscaleInterface("missing-registered-utun"); err == nil || got != nil {
		t.Fatalf("removed tunnel = %v, %v", got, err)
	}
}

func TestRegisteredTunnelBinding(t *testing.T) {
	name, _ := netmon.TailscaleInterfaceName()
	index, _ := netmon.TailscaleInterfaceIndex()
	t.Cleanup(func() { netmon.SetTailscaleInterfaceProps(name, index) })

	idx, err := netmon.DefaultRouteInterfaceIndex()
	if errors.Is(err, netmon.ErrNoGatewayIndexFound) {
		t.Skip("requires a default route")
	}
	if err != nil {
		t.Fatal(err)
	}
	def, err := net.InterfaceByIndex(idx)
	if err != nil {
		t.Fatal(err)
	}
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}

	mon := netmon.NewStatic()
	for _, tc := range []struct {
		name       string
		monitor    *netmon.Monitor
		registered string
		savedIndex int
		guess      *net.Interface
		wantIndex  int
		wantErr    error
	}{
		{"registered/monitored", mon, def.Name, lo.Index, nil, 0, errTunnelUnderlay},
		{"registered/unmonitored", nil, def.Name, lo.Index, nil, 0, errTunnelUnderlay},
		{"heuristic/monitored", mon, "", 0, def, 0, nil},
		{"heuristic/unmonitored", nil, "", 0, def, idx, nil},
		{"no-match/monitored", mon, "", 0, nil, idx, nil},
		{"no-match/unmonitored", nil, "", 0, nil, idx, nil},
		// The registered index may now belong to another device.
		{"reused-index/monitored", mon, lo.Name, idx, def, idx, nil},
		{"reused-index/unmonitored", nil, lo.Name, idx, def, idx, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			netmon.SetTailscaleInterfaceProps(tc.registered, tc.savedIndex)
			tstest.Replace(t, &guessTailscaleInterface, func() (*net.Interface, error) { return tc.guess, nil })
			got, err := listenDefaultInterface(t, tc.monitor)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ListenPacket: %v, want %v", err, tc.wantErr)
			}
			if err == nil && got != tc.wantIndex {
				t.Errorf("IP_BOUND_IF = %d, want %d", got, tc.wantIndex)
			}
		})
	}
}

func listenDefaultInterface(t *testing.T, mon *netmon.Monitor) (int, error) {
	t.Helper()
	var bound int
	lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
		// An empty destination host selects the default in either route mode.
		if err := controlLogf(t.Logf, mon, network, ":0", c); err != nil {
			return err
		}
		var optErr error
		if err := c.Control(func(fd uintptr) {
			bound, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF)
		}); err != nil {
			return err
		}
		return optErr
	}}
	conn, err := lc.ListenPacket(t.Context(), "udp4", ":0")
	if err == nil {
		conn.Close()
	}
	return bound, err
}
