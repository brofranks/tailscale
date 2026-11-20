// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/wgengine/router"
)

func TestPFEnumerationFailurePreservesAnchor(t *testing.T) {
	listErr := errors.New("interface list unavailable")
	tstest.Replace(t, &pfListInterfaces, func() ([]net.Interface, error) { return nil, listErr })
	const command = `#!/bin/sh
case "$*" in
    "-f -") /bin/cat > main-rules ;;
    "-a tailscale -f -") /bin/cat > anchor ;;
    "-a tailscale -F all") : > anchor ;;
esac
`
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	for _, name := range []string{"pfctl", "kldload", "sysctl"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(command), 0700); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct{ name, anchor string }{
		{"empty", ""},
		{"populated", "pass out all\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile("anchor", []byte(tc.anchor), 0600); err != nil {
				t.Fatal(err)
			}
			r := &freebsdRouter{
				userspaceBSDRouter: &userspaceBSDRouter{logf: t.Logf, tunname: "tun0"},
				kernelSubnets:      true,
			}
			cfg := &router.Config{
				SubnetRoutes:     []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
				SNATSubnetRoutes: true,
			}
			if err := r.Set(cfg); !errors.Is(err, listErr) {
				t.Fatalf("enable SNAT = %v, want %v", err, listErr)
			}
			if err := r.Set(nil); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile("main-rules"); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("main PF ruleset write = %q, %v, want no write", got, err)
			}
			got, err := os.ReadFile("anchor")
			if err != nil || string(got) != tc.anchor {
				t.Errorf("anchor = %q, %v, want %q", got, err, tc.anchor)
			}
		})
	}
}

func TestPFTablesReferenced(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		want  []string
	}{
		{"empty", "", nil},
		{
			// What a bare FreeBSD box looks like: only our anchor refs.
			"anchors only",
			"nat-anchor \"tailscale\"\nanchor \"tailscale\"\n",
			nil,
		},
		{
			"no tables",
			"scrub in all fragment reassemble\npass in all flags S/SA keep state\n",
			nil,
		},
		{
			// pfctl emits automatic tables like this for interface groups; a
			// reload without table preservation would empty them too.
			"automatic table",
			"block drop in log inet from <__automatic_591ee83a_0> to any\n",
			[]string{"__automatic_591ee83a_0"},
		},
		{
			"named table",
			"pass out log on em0 proto tcp from <zabbix_proxies> to any port = ssh\n",
			[]string{"zabbix_proxies"},
		},
		{
			"deduplicated and sorted",
			"pass in log from <trusted> to any\n" +
				"pass in log from <admins> to any\n" +
				"pass out log from any to <trusted>\n",
			[]string{"admins", "trusted"},
		},
		{
			"names with punctuation",
			"pass in log from <fw-cluster.v4> to any\npass in log from <mon_hosts> to any\n",
			[]string{"fw-cluster.v4", "mon_hosts"},
		},
		{
			// A bare "<" with no closing ">" is not a table reference.
			"unclosed angle bracket",
			"pass in all # < not a table\n",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pfTablesReferenced(tt.rules); !slices.Equal(got, tt.want) {
				t.Errorf("pfTablesReferenced() = %v, want %v", got, tt.want)
			}
		})
	}
}
