// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"testing"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/config"
)

func baseArgs() Args {
	a := Args{
		AltWordList:       stringset.New(),
		AltWordListMask:   stringset.New(),
		BruteWordList:     stringset.New(),
		BruteWordListMask: stringset.New(),
		Blacklist:         stringset.New(),
		Domains:           stringset.New(),
		Excluded:          stringset.New(),
		Included:          stringset.New(),
		Names:             stringset.New(),
		Resolvers:         stringset.New(),
	}
	return a
}

// -active-proxy flows into the config, and -active-strict overrides the
// config default (true) only when the operator actually supplied the flag.
func TestOverrideConfigActiveProxy(t *testing.T) {
	t.Run("proxy set, strict not supplied keeps default true", func(t *testing.T) {
		a := baseArgs()
		a.ActiveProxy = "socks5://127.0.0.1:1080"
		c := config.NewConfig() // ActiveStrict defaults to true
		if err := a.OverrideConfig(c); err != nil {
			t.Fatal(err)
		}
		if c.ActiveProxy != "socks5://127.0.0.1:1080" {
			t.Errorf("ActiveProxy = %q", c.ActiveProxy)
		}
		if !c.ActiveStrict {
			t.Error("ActiveStrict should stay true when -active-strict was not supplied")
		}
	})

	t.Run("strict explicitly disabled is honoured", func(t *testing.T) {
		a := baseArgs()
		a.Options.ActiveStrict = false
		a.Options.ActiveStrictSet = true
		c := config.NewConfig()
		if err := a.OverrideConfig(c); err != nil {
			t.Fatal(err)
		}
		if c.ActiveStrict {
			t.Error("ActiveStrict should be false when -active-strict=false was supplied")
		}
	})

	t.Run("strict value ignored when flag not supplied", func(t *testing.T) {
		a := baseArgs()
		a.Options.ActiveStrict = false // default flag value, but not supplied
		a.Options.ActiveStrictSet = false
		c := config.NewConfig()
		if err := a.OverrideConfig(c); err != nil {
			t.Fatal(err)
		}
		if !c.ActiveStrict {
			t.Error("an unsupplied -active-strict must not override the config default")
		}
	})
}
