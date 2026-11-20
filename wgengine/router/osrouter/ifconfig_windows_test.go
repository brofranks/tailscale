// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/tsaddr"
)

func randIP() netip.Addr {
	b := byte(rand.Intn(3))
	return netip.AddrFrom4([4]byte{b, b, b, b})
}

func randRouteData() *routeData {
	return &routeData{
		RouteData: winipcfg.RouteData{
			Destination: netip.PrefixFrom(randIP(), rand.Intn(30)+1),
			NextHop:     randIP(),
			Metric:      uint32(rand.Intn(3)),
		},
	}
}

type W = winipcfg.RouteData

func TestRouteLess(t *testing.T) {
	type D = routeData
	ipnet := netip.MustParsePrefix
	tests := []struct {
		ri, rj *routeData
		want   bool
	}{
		{
			ri:   &D{RouteData: W{Metric: 1}},
			rj:   &D{RouteData: W{Metric: 2}},
			want: true,
		},
		{
			ri:   &D{RouteData: W{Destination: ipnet("1.1.0.0/16"), Metric: 2}},
			rj:   &D{RouteData: W{Destination: ipnet("2.2.0.0/16"), Metric: 1}},
			want: true,
		},
		{
			ri:   &D{RouteData: W{Destination: ipnet("1.1.0.0/16"), Metric: 1}},
			rj:   &D{RouteData: W{Destination: ipnet("2.2.0.0/16"), Metric: 1}},
			want: true,
		},
		{
			ri:   &D{RouteData: W{Destination: ipnet("1.1.0.0/32"), Metric: 2}},
			rj:   &D{RouteData: W{Destination: ipnet("1.1.0.0/16"), Metric: 1}},
			want: true,
		},
		{
			ri:   &D{RouteData: W{Destination: ipnet("1.1.0.0/32"), Metric: 1}},
			rj:   &D{RouteData: W{Destination: ipnet("1.1.0.0/16"), Metric: 1}},
			want: true,
		},
		{
			ri:   &D{RouteData: W{Destination: ipnet("1.1.0.0/16"), Metric: 1, NextHop: netip.MustParseAddr("3.3.3.3")}},
			rj:   &D{RouteData: W{Destination: ipnet("1.1.0.0/16"), Metric: 1, NextHop: netip.MustParseAddr("4.4.4.4")}},
			want: true,
		},
	}
	for i, tt := range tests {
		got := tt.ri.Less(tt.rj)
		if got != tt.want {
			t.Errorf("%v. less = %v; want %v", i, got, tt.want)
		}
		back := tt.rj.Less(tt.ri)
		if back && got {
			t.Errorf("%v. less both ways", i)
		}
	}
}

func TestRouteDataLessConsistent(t *testing.T) {
	for range 10000 {
		ri := randRouteData()
		rj := randRouteData()
		if ri.Less(rj) && rj.Less(ri) {
			t.Fatalf("both compare less to each other:\n\t%#v\nand\n\t%#v", ri, rj)
		}
	}
}

func nets(cidrs ...string) (ret []netip.Prefix) {
	for _, s := range cidrs {
		ret = append(ret, netip.MustParsePrefix(s))
	}
	return
}

func nilIfEmpty[E any](s []E) []E {
	if len(s) == 0 {
		return nil
	}
	return s
}

func TestDeltaNets(t *testing.T) {
	tests := []struct {
		a, b             []netip.Prefix
		wantAdd, wantDel []netip.Prefix
	}{
		{
			a:       nets("1.2.3.4/24", "1.2.3.4/31", "1.2.3.3/32", "10.0.1.1/32", "100.0.1.1/32"),
			b:       nets("10.0.1.1/32", "100.0.2.1/32", "1.2.3.3/32", "1.2.3.4/24"),
			wantAdd: nets("100.0.2.1/32"),
			wantDel: nets("1.2.3.4/31", "100.0.1.1/32"),
		},
		{
			a:       nets("fe80::99d0:ec2d:b2e7:536b/64", "100.84.36.11/32"),
			b:       nets("100.84.36.11/32"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
		{
			a:       nets("100.84.36.11/32", "fe80::99d0:ec2d:b2e7:536b/64"),
			b:       nets("100.84.36.11/32"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
		{
			a:       nets("100.84.36.11/32", "fe80::99d0:ec2d:b2e7:536b/64"),
			b:       nets("100.84.36.11/32"),
			wantDel: nets("fe80::99d0:ec2d:b2e7:536b/64"),
		},
	}
	for i, tt := range tests {
		add, del := deltaNets(tt.a, tt.b)
		if !reflect.DeepEqual(nilIfEmpty(add), nilIfEmpty(tt.wantAdd)) {
			t.Errorf("[%d] add:\n  got: %v\n want: %v\n", i, add, tt.wantAdd)
		}
		if !reflect.DeepEqual(nilIfEmpty(del), nilIfEmpty(tt.wantDel)) {
			t.Errorf("[%d] del:\n  got: %v\n want: %v\n", i, del, tt.wantDel)
		}
	}
}

func formatRouteData(rds []*routeData) string {
	var b strings.Builder
	for _, rd := range rds {
		b.WriteString(fmt.Sprintf("%+v", rd))
	}
	return b.String()
}

func equalRouteDatas(a, b []*routeData) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Compare(b[i]) != 0 {
			return false
		}
	}
	return true
}

func ipnet4(ip string, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.MustParseAddr(ip), bits)
}

func TestFilterRoutes(t *testing.T) {
	const (
		local  = winipcfg.RouteProtocolLocal
		static = winipcfg.RouteProtocolNetMgmt
	)
	route := func(prefix, hop string, proto winipcfg.RouteProtocol) *routeData {
		return &routeData{
			RouteData: W{
				Destination: netip.MustParsePrefix(prefix),
				NextHop:     netip.MustParseAddr(hop),
			},
			Row: &winipcfg.MibIPforwardRow2{Protocol: proto},
		}
	}
	assigned := mustCIDRs("100.64.0.16/32", "192.0.2.17/24", "fd42::10/128", "fd42::21/64")
	kernel := []*routeData{
		// Link-local and loopback broadcast routes.
		route("169.254.255.255/32", "0.0.0.0", local),
		route("127.255.255.255/32", "0.0.0.0", local),
		// Hosts, connected subnets and broadcast routes for local addresses.
		route("100.64.0.16/32", "0.0.0.0", local),
		route("192.0.2.17/32", "0.0.0.0", local),
		route("192.0.2.0/24", "0.0.0.0", local),
		route("192.0.2.255/32", "0.0.0.0", local),
		route("fd42::10/128", "::", local),
		route("fd42::21/128", "::", local),
		route("fd42::/64", "::", local),
	}
	want := []*routeData{
		// A routed subnet and a peer at its last address in each family.
		route("100.64.0.16/28", "100.100.100.100", static),
		route("100.64.0.31/32", "0.0.0.0", static),
		route("fd42::10/124", "fd7a:115c:a1e0::53", static),
		route("fd42::1f/128", "fd7a:115c:a1e0::53", static),
		// A static route can share a prefix with a connected route.
		route("192.0.2.0/24", "100.100.100.100", static),
	}

	got := filterRoutes(slices.Concat(kernel, want), assigned)
	add, del := deltaRouteData(got, want)
	if len(add) != 0 || len(del) != 0 {
		t.Errorf("repeat sync: add %v, delete %v", formatRouteData(add), formatRouteData(del))
	}

	// Unassigned subnets and withdrawn peer routes are still deletable.
	stale := []*routeData{
		route("169.254.0.0/16", "0.0.0.0", local),
		route("127.0.0.0/8", "0.0.0.0", local),
	}
	got = filterRoutes(slices.Concat(kernel, want, stale), assigned)
	_, del = deltaRouteData(got, nil)
	wantDel := slices.Concat(want, stale)
	slices.SortFunc(wantDel, (*routeData).Compare)
	if !equalRouteDatas(del, wantDel) {
		t.Errorf("withdraw routes: delete %v, want %v", formatRouteData(del), formatRouteData(wantDel))
	}

	// An IPv4-only configuration with IPv6 routes gains a local IPv6 address.
	ip := tsaddr.Tailscale4To6Placeholder()
	placeholder := netip.PrefixFrom(ip, ip.BitLen())
	got = filterRoutes(
		[]*routeData{route(placeholder.String(), "::", local)},
		[]netip.Prefix{placeholder},
	)
	_, del = deltaRouteData(got, nil)
	if len(del) != 0 {
		t.Errorf("delete IPv6 placeholder: %v", formatRouteData(del))
	}
}

func TestDeltaRouteData(t *testing.T) {
	var h0 netip.Addr
	h1 := netip.MustParseAddr("99.99.99.99")
	h2 := netip.MustParseAddr("99.99.9.99")

	a := []*routeData{
		{RouteData: W{ipnet4("1.2.3.4", 32), h0, 1}},
		{RouteData: W{ipnet4("1.2.3.4", 24), h1, 2}},
		{RouteData: W{ipnet4("1.2.3.4", 24), h2, 1}},
		{RouteData: W{ipnet4("1.2.3.5", 32), h0, 1}},
	}
	b := []*routeData{
		{RouteData: W{ipnet4("1.2.3.5", 32), h0, 1}},
		{RouteData: W{ipnet4("1.2.3.4", 24), h1, 2}},
		{RouteData: W{ipnet4("1.2.3.4", 24), h2, 2}},
	}
	add, del := deltaRouteData(a, b)

	wantAdd := []*routeData{
		{RouteData: W{ipnet4("1.2.3.4", 24), h2, 2}},
	}
	wantDel := []*routeData{
		{RouteData: W{ipnet4("1.2.3.4", 32), h0, 1}},
		{RouteData: W{ipnet4("1.2.3.4", 24), h2, 1}},
	}

	if !equalRouteDatas(add, wantAdd) {
		t.Errorf("add:\n   got: %v\n  want: %v\n", formatRouteData(add), formatRouteData(wantAdd))
	}
	if !equalRouteDatas(del, wantDel) {
		t.Errorf("del:\n   got: %v\n  want: %v\n", formatRouteData(del), formatRouteData(wantDel))
	}
}
