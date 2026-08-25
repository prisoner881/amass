// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// plugin.go registers protocol_probes on oam.IPAddress, Position 43 -
// confirmed clear of every other handler already registered on this
// event type (ip_netblock:4, bgptools:2, dns:8, horizontals:10,
// http_probes:42) before this position was chosen. This runs
// independently of http_probes, coordinating with it only through
// observable database state (certharvest.go's dedup guard), not
// through any direct call between the two plugins - each reads its own
// separate configured port list and neither needs to know the other
// exists.

// peekTimeout bounds how long the banner-peek step waits per port
// before concluding a port is silent. Short and deliberate: a real
// banner-first service greets immediately, so there is no reason to
// wait long to find out nothing is coming.
const peekTimeout = 2 * time.Second

// ambiguousBannerDBs are the Recog fingerprint databases tried, in
// order, for a banner that arrived but wasn't unambiguously classified
// as SSH. This is the mechanism that resolves genuine ambiguity (SMTP
// and FTP both commonly opening with the same "220 " prefix) rather
// than guessing at the classification layer.
var ambiguousBannerDBs = []string{
	"smtp_banners.xml",
	"ftp_banners.xml",
	"pop_banners.xml",
	"telnet_banners.xml",
}

type protocolProbes struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewProtocolProbes() et.Plugin {
	return &protocolProbes{
		name: "Protocol-Probes",
		source: &et.Source{
			Name:       "Protocol-Probes",
			Confidence: 80,
		},
	}
}

func (pp *protocolProbes) Name() string {
	return pp.name
}

func (pp *protocolProbes) Start(r et.Registry) error {
	pp.log = r.Log().WithGroup("plugin").With("name", pp.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       pp,
		Name:         pp.name + "-IPAddress-Handler",
		Position:     43,
		MaxInstances: support.MidHandlerInstances,
		Transforms: []string{
			string(oam.Service),
			string(oam.TLSCertificate),
			string(oam.Product),
			string(oam.ProductRelease),
		},
		EventType: oam.IPAddress,
		Callback:  pp.check,
	}); err != nil {
		return err
	}

	pp.log.Info("Plugin started")
	return nil
}

func (pp *protocolProbes) Stop() {
	pp.log.Info("Plugin stopped")
}

func (pp *protocolProbes) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	// Genuinely active probing (banner peeks and TLS handshakes touch
	// the target directly) - gated on -active the same way every other
	// active-probing plugin in this codebase already is.
	if !e.Session.Config().Active {
		return nil
	}

	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf <= 0 {
		return nil
	}

	ports := e.Session.Config().Scope.ProtocolProbePorts
	if len(ports) == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), pp.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, pp.source, since) {
		return nil
	}

	addr := ip.Address.String()
	for _, port := range ports {
		pp.probeOnePort(e, addr, port)
	}

	support.MarkAssetMonitored(e.Session, e.Entity, pp.source)
	return nil
}

// probeOnePort peeks a single port, classifies whatever (if anything)
// arrived, and routes to the appropriate next step. Errors from any
// individual port are logged and otherwise swallowed - one unreachable
// or misbehaving port should never prevent the remaining configured
// ports from being tried.
func (pp *protocolProbes) probeOnePort(e *et.Event, addr string, port int) {
	target := net.JoinHostPort(addr, strconv.Itoa(port))

	result := PeekBanner(e.Session.Ctx(), target, peekTimeout)
	if result.Err != nil {
		return
	}

	switch ClassifyPeek(result.Data) {
	case GuessSSH:
		pp.handleSSH(e, addr, port, string(result.Data))
	case GuessAmbiguousBanner:
		pp.handleAmbiguousBanner(e, addr, port, string(result.Data))
	case GuessSilent:
		// Consistent with existing implicit-TLS ports: a service that
		// sends nothing before the client speaks is exactly the
		// signature of HTTPS or any other implicit-TLS protocol.
		// certharvest.go's own dedup guard means this is a genuine
		// no-op, not wasted work, if http_probes already harvested a
		// certificate here.
		if err := HarvestCertificate(e, e.Entity, target, port, peekTimeout); err != nil {
			pp.log.Warn("certificate harvest failed", "target", target, "error", err.Error())
		}
	}
}

// handleSSH stores the Service entity for a definite SSH port and
// attempts Recog identification against ssh_banners.xml specifically -
// no cert harvest is attempted, since SSH does not present an X.509
// certificate in the common case (see the earlier design discussion
// for why this genuinely differs from every other protocol here).
func (pp *protocolProbes) handleSSH(e *et.Event, addr string, port int, banner string) {
	pp.storeServiceAndIdentify(e, addr, port, "ssh", banner, []string{"ssh_banners.xml"})
}

// handleAmbiguousBanner stores the Service entity for a banner-first
// port whose specific protocol wasn't determined by classification
// alone, and lets Recog's own fingerprint matching resolve it. No cert
// harvest is attempted here either - a plaintext banner arriving
// unprompted on a non-implicit-TLS port means no TLS handshake has
// occurred at all; that would only become possible via a STARTTLS-style
// negotiation, deliberately out of scope for this stage of the project.
func (pp *protocolProbes) handleAmbiguousBanner(e *et.Event, addr string, port int, banner string) {
	pp.storeServiceAndIdentify(e, addr, port, "unknown-banner", banner, ambiguousBannerDBs)
}

// storeServiceAndIdentify creates the Service entity for a banner-first
// port (Output holds the raw banner - the exact same field Tech-Stack
// already reads generically for any Service, HTTP-sourced or not) and,
// if Recog recognizes the banner against any of the given databases,
// creates the corresponding Product/ProductRelease entities.
func (pp *protocolProbes) storeServiceAndIdentify(e *et.Event, addr string, port int, svcType, banner string, dbNames []string) {
	svcEntity, err := FindOrCreateService(e, e.Entity, addr, port, svcType, banner)
	if err != nil {
		pp.log.Warn("failed to store the Service asset", "addr", addr, "port", port, "error", err.Error())
		return
	}

	match, ok := MatchAnyBanner(banner, dbNames...)
	if !ok {
		return
	}
	storeRecogMatch(e, svcEntity, pp.source, match)
}
