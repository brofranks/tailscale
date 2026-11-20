// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package osrouter contains OS-specific router implementations.
// This package has no API; it exists purely to import
// for the side effect of it registering itself with the wgengine/router
// package.
package osrouter

import (
	"net/netip"
	"slices"

	"tailscale.com/net/tsaddr"
	"tailscale.com/wgengine/router"
)

// shutdownConfig is a routing configuration that removes all router
// state from the OS. It's the config used when callers pass in a nil
// Config.
var shutdownConfig router.Config

// windowsRouteNextHop returns the next hop Windows reports for a route.
// An invalid address skips a host route the kernel already supplies.
func windowsRouteNextHop(
	route netip.Prefix,
	gateway netip.Addr,
	assigned []netip.Prefix,
) netip.Addr {
	isAssigned := func(ip netip.Addr) bool {
		return slices.ContainsFunc(assigned, func(p netip.Prefix) bool {
			return p.Addr().Unmap() == ip
		})
	}
	dest := route.Addr().Unmap()
	if route.IsSingleIP() && isAssigned(dest) {
		// Replacing the host route can make the adapter IP unreachable.
		return netip.Addr{}
	}
	// Host routes to the gateway and single Tailscale IPs are on-link.
	// Windows also reports an assigned next hop as the unspecified address.
	if (route.IsSingleIP() && (dest == gateway || tsaddr.IsTailscaleIP(dest))) ||
		isAssigned(gateway) {
		if route.Addr().Is4() {
			return netip.IPv4Unspecified()
		}
		return netip.IPv6Unspecified()
	}
	return gateway
}
