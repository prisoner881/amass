// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"net"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

// The start-up proxy check is the only proxy check the engine makes, so a
// session must not be created while the proxy is down. Both refusals happen
// before CreateSession touches the manager, registry or database.
func TestCreateSessionRefusesDeadProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()

	cfg := config.NewConfig()
	cfg.Active = true
	cfg.ActiveProxy = "socks5h://" + dead

	_, err = CreateSession(nil, nil, cfg)
	if err == nil || !strings.Contains(err.Error(), "is not usable") {
		t.Fatalf("want a refusal naming the unusable proxy, got %v", err)
	}
}

func TestCreateSessionRefusesStrictWithoutProxy(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Active = true // strict is on by default, no proxy

	if _, err := CreateSession(nil, nil, cfg); err == nil || !strings.Contains(err.Error(), "requires an active_proxy") {
		t.Fatalf("want a refusal for active+strict without a proxy, got %v", err)
	}
}
