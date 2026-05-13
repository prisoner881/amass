// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateActiveProxyURL(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantErr  bool
		errMatch string
	}{
		{"empty", "", true, "empty"},
		{"missing scheme", "127.0.0.1:8080", true, "scheme"},
		{"no host", "http://", true, "host"},
		{"unsupported scheme", "ftp://proxy.example:8080", true, "not supported"},
		{"http ok", "http://proxy.example:8080", false, ""},
		{"socks5 ok", "socks5://10.0.0.1:1080", false, ""},
		{"socks5h ok", "socks5h://10.0.0.1:1080", false, ""},
		{"https ok with auth", "https://user:pass@proxy.example:443", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateActiveProxyURL(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errMatch != "" && !strings.Contains(err.Error(), tc.errMatch) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errMatch)
			}
		})
	}
}

func TestCheckSettings_ActiveProxyEnforcement(t *testing.T) {
	t.Run("active + no proxy + strict => error", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		// NewConfig sets ActiveStrict=true; do not override.
		if err := c.CheckSettings(); err == nil ||
			!strings.Contains(err.Error(), "active_proxy") {
			t.Fatalf("expected fail-closed error mentioning active_proxy, got: %v", err)
		}
	})

	t.Run("active + proxy + strict => ok", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		c.ActiveProxy = "socks5://127.0.0.1:1080"
		if err := c.CheckSettings(); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	t.Run("active + no proxy + non-strict => ok", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		c.ActiveStrict = false
		if err := c.CheckSettings(); err != nil {
			t.Fatalf("expected no error with strict off, got: %v", err)
		}
	})

	t.Run("active + invalid proxy URL => error", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		c.ActiveProxy = "not a url"
		if err := c.CheckSettings(); err == nil {
			t.Fatalf("expected error for invalid proxy URL")
		}
	})

	t.Run("passive run with strict default => ok", func(t *testing.T) {
		c := NewConfig()
		c.Active = false
		if err := c.CheckSettings(); err != nil {
			t.Fatalf("strict default should not affect non-active runs, got: %v", err)
		}
	})
}

func TestLoadActiveProxySettings(t *testing.T) {
	c := NewConfig()
	c.Options["active_proxy"] = "http://10.0.0.1:3128"
	c.Options["active_strict"] = false

	if err := c.loadActiveProxySettings(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ActiveProxy != "http://10.0.0.1:3128" {
		t.Errorf("ActiveProxy not loaded, got %q", c.ActiveProxy)
	}
	if c.ActiveStrict != false {
		t.Errorf("ActiveStrict not loaded from options, got %v", c.ActiveStrict)
	}

	t.Run("non-string active_proxy", func(t *testing.T) {
		c := NewConfig()
		c.Options["active_proxy"] = 42
		if err := c.loadActiveProxySettings(c); err == nil {
			t.Fatalf("expected error for non-string active_proxy")
		}
	})

	t.Run("non-bool active_strict", func(t *testing.T) {
		c := NewConfig()
		c.Options["active_strict"] = "yes"
		if err := c.loadActiveProxySettings(c); err == nil {
			t.Fatalf("expected error for non-bool active_strict")
		}
	})
}
