// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"net/netip"
	"testing"
)

func mustCIDRs(ss ...string) []netip.Prefix {
	var ret []netip.Prefix
	for _, s := range ss {
		ret = append(ret, netip.MustParsePrefix(s))
	}
	return ret
}

func TestWindowsRouteNextHop(t *testing.T) {
	const gw4, gw6 = "100.100.100.100", "fd7a:115c:a1e0::53"
	assigned := mustCIDRs("fd42::10/128", "fd42::21/64", "10.0.0.16/32", "10.0.0.17/32")
	for _, tc := range []struct{ route, gateway, want string }{
		{"fd42::10/124", gw6, gw6},
		{"fd42::10/128", gw6, ""},
		{"fd42::21/128", gw6, ""},
		{"fd42::22/128", gw6, gw6},
		{"10.0.0.16/28", gw4, gw4},
		{"10.0.0.17/32", gw4, ""},
		{gw4 + "/32", gw4, "0.0.0.0"},
		{"100.64.0.7/32", gw4, "0.0.0.0"},
		{"::/0", gw6, gw6},
		{"fd42::10/124", "fd42::21", "::"},
		{"10.0.0.16/28", "10.0.0.17", "0.0.0.0"},
	} {
		var want netip.Addr
		if tc.want != "" {
			want = netip.MustParseAddr(tc.want)
		}
		got := windowsRouteNextHop(netip.MustParsePrefix(tc.route), netip.MustParseAddr(tc.gateway), assigned)
		if got != want {
			t.Errorf("route %s via %s: next hop = %v, want %v", tc.route, tc.gateway, got, want)
		}
	}
}
