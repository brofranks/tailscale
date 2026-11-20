// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
)

// TestDaemonLocalDNS checks that a running tailscaled answers a
// control-supplied record from its own resolver.
func TestDaemonLocalDNS(t *testing.T) {
	env := NewTestEnv(t)
	const host = "node.example.com."
	const want = "192.0.2.53"
	env.Control.DNSConfig = &tailcfg.DNSConfig{
		Proxied:      true,
		Routes:       map[string][]*dnstype.Resolver{"example.com.": nil},
		ExtraRecords: []tailcfg.DNSRecord{{Name: host, Value: want}},
	}
	n := NewTestNode(t, env)
	d := n.StartDaemon()
	defer d.MustCleanShutdown(t)
	n.AwaitResponding()
	n.MustUp()
	n.AwaitRunning()
	if err := tstest.WaitFor(7*time.Second, func() error {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		v, _, err := n.LocalClient().QueryDNS(ctx, host, "A")
		if err != nil {
			return err
		}
		var m dns.Msg
		if err := m.Unpack(v); err != nil {
			return err
		}
		if len(m.Answer) == 1 {
			if a, ok := m.Answer[0].(*dns.A); ok && a.A.String() == want {
				return nil
			}
		}
		return fmt.Errorf("rcode %s, answers %v", dns.RcodeToString[m.Rcode], m.Answer)
	}); err != nil {
		t.Error(err)
	}
}
