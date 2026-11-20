// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"path/filepath"
	"testing"
)

func TestGetNetshPath(t *testing.T) {
	ft := &firewallTweaker{
		logf: t.Logf,
	}
	path := ft.getNetshPath()
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path for netsh.exe: %q", path)
	}
}

func TestCloseBeforeUpLeavesFirewallUnused(t *testing.T) {
	r := &winRouter{firewall: &firewallTweaker{logf: func(format string, args ...any) {
		// Fail on the synchronous request, before a worker can run netsh.
		t.Fatalf(format, args...)
	}}}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
