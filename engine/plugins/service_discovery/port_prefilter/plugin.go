// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package port_prefilter is a cheap, high-volume liveness check that
// sits ahead of http_probes and protocol_probes in the pipeline.
// Neither of those plugins can afford to run their own, much more
// expensive per-port work (a full banner-peek/TLS-handshake cycle, or
// an active HTTP request) against every port in a broad, nmap-top-
// 1000-scale scan range - most ports on any given host are closed or
// filtered, and paying each one's full timeout serially is the
// dominant cost identified in the design discussion this plugin comes
// from. This plugin's only job is to answer "is anything listening
// here at all" via a plain TCP connect-and-immediately-close, cheap
// enough to run across a much broader port range than either
// identification plugin could reasonably attempt on its own.
//
// The actual scan and its caching/TTL logic live in
// support.EnsureOpenPortsScanned, shared with http_probes'
// fqdn_endpoint.go - this plugin is a thin wrapper around that shared
// function on its own, guaranteed-ordering IPAddress pipeline
// position, not a second, separate implementation. See that
// function's own doc comment for the full design reasoning, including
// why a shared entry point is needed at all rather than one plugin
// simply reading what the other already wrote.
//
// Deliberately not a raw SYN scan - that would require CAP_NET_RAW
// privileges this container doesn't have and shouldn't need, and
// carries a real, if narrow, risk of false negatives against
// firewalls specifically tuned to stay silent against a bare,
// isolated SYN with no follow-through while responding normally to a
// genuine connection attempt. A full connect scan is slower per port
// than a true SYN scan would be, but needs no elevated privileges,
// carries no comparable stealth-firewall risk, and doesn't meaningfully
// increase this deployment's existing scan signature beyond what
// http_probes and protocol_probes already do today.
package port_prefilter

import (
	"errors"
	"log/slog"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type portPrefilter struct {
	name string
	log  *slog.Logger
}

func NewPortPrefilter() et.Plugin {
	return &portPrefilter{name: "Port-Prefilter"}
}

func (pp *portPrefilter) Name() string {
	return pp.name
}

func (pp *portPrefilter) Start(r et.Registry) error {
	pp.log = r.Log().WithGroup("plugin").With("name", pp.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       pp,
		Name:         pp.name + "-Handler",
		Position:     41,
		Exclusive:    true,
		MaxInstances: support.HighHandlerInstances,
		EventType:    oam.IPAddress,
		Callback:     pp.check,
	}); err != nil {
		return err
	}

	pp.log.Info("Plugin started")
	return nil
}

func (pp *portPrefilter) Stop() {}

func (pp *portPrefilter) check(e *et.Event) error {
	if _, ok := e.Entity.Asset.(*oamnet.IPAddress); !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	// Genuinely active probing (real TCP connect attempts against the
	// target) - gated on -active the same way every other
	// active-probing plugin in this codebase already is.
	if !e.Session.Config().Active {
		return nil
	}

	support.EnsureOpenPortsScanned(e, e.Entity, selectDialer(e))
	return nil
}

// selectDialer mirrors protocol_probes' own function of the same name
// and purpose exactly - a single, deliberate integration point for
// feature/active-proxy-egress once merged, so this plugin
// automatically inherits proxy-routed egress without any further
// changes here, the same reasoning behind PeekBanner's own dial
// injection in protocol_probes/banner_peek.go. A nil dial (the only
// option this branch has available today) falls back to
// support.scanPorts' own use of amassnet.NewDialContext.
func selectDialer(e *et.Event) amassnet.DialContext {
	return amassnet.NewDialContext(support.PortPrefilterScanTimeout)
}
