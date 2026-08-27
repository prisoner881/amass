// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// plugin.go registers protocol_probes on oam.IPAddress, Position 43 -
// confirmed clear of every other handler already registered on this
// event type (ip_netblock:4, bgptools:2, dns:8, horizontals:10,
// http_probes:42) before this position was chosen. This runs
// independently of http_probes as a plugin (each has its own handler,
// its own registration, its own database writes), but the two now
// deliberately share the same aggregate Scope.Ports list and the same
// banner-peek/classify logic (PeekBanner, ClassifyPeek, PeekTimeout,
// all exported specifically so http_probes can call them directly) -
// this is what lets http_probes skip a pointless HTTP attempt against
// a port that peeks as unambiguously non-HTTP (e.g. an SSH banner),
// rather than the two plugins working from separate port lists with no
// coordination at all. Certificate harvesting still coordinates only
// through observable database state (certharvest.go's dedup guard),
// not a direct call - that part hasn't changed.

// PeekTimeout bounds how long the banner-peek step waits per port
// before concluding a port is silent. Short and deliberate: a real
// banner-first service greets immediately, so there is no reason to
// wait long to find out nothing is coming. Exported so http_probes can
// use the exact same bound when it performs its own peek, rather than
// risking two different timeouts drifting apart over time.
const PeekTimeout = 2 * time.Second

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

// selectDialer is the single, deliberately isolated place that decides
// which dialer this plugin's active-only traffic (banner peeks, raw
// TLS cert handshakes) actually uses. On this branch today it can only
// ever return the plain, direct dialer - the active-proxy-egress
// mechanism (Session.ActiveEgress(), Config().ActiveStrict) doesn't
// exist on main yet, so there is nothing else to select.
//
// *** REQUIRED UPDATE ONCE MERGED WITH feature/active-proxy-egress ***
// Replace this function's body with the exact same pattern JARM's own
// raw dial already uses on that branch, in
// engine/plugins/support/fingerprinting.go:
//
//	var dial amassnet.DialContext
//	if ae := e.Session.ActiveEgress(); ae != nil {
//	    dial = ae.DialContext
//	} else if e.Session.Config().ActiveStrict {
//	    return nil, amassnet.ErrNoActiveEgress
//	} else {
//	    dial = amassnet.NewDialContext(PeekTimeout)
//	}
//
// Every other line in this package - PeekBanner, HarvestCertificate,
// dialAndGetCertChain - already accepts an injected amassnet.DialContext
// and needs no further changes; this function is the only integration
// point.
func selectDialer(e *et.Event) amassnet.DialContext {
	return amassnet.NewDialContext(PeekTimeout)
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
	// TEMPORARY DIAGNOSTIC - remove once the missing-Service investigation
	// is resolved. Writes directly to stderr, bypassing any uncertainty
	// about where slog/syslog output actually ends up, to answer one
	// specific question: is this function being called at all.
	fmt.Fprintf(os.Stderr, "DEBUG protocol_probes check() called for %v\n", e.Entity.Asset.Key())

	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		fmt.Fprintf(os.Stderr, "DEBUG protocol_probes EXIT type-assertion for %v\n", e.Entity.Asset.Key())
		return errors.New("failed to extract the IPAddress asset")
	}

	// Genuinely active probing (banner peeks and TLS handshakes touch
	// the target directly) - gated on -active the same way every other
	// active-probing plugin in this codebase already is.
	if !e.Session.Config().Active {
		fmt.Fprintf(os.Stderr, "DEBUG protocol_probes EXIT not-active for %v\n", ip.Address.String())
		return nil
	}

	if _, conf := e.Session.Scope().IsAssetInScope(e.Entity.Asset, 0); conf <= 0 {
		nblocks := e.Session.Scope().Netblocks()
		fmt.Fprintf(os.Stderr, "DEBUG protocol_probes EXIT out-of-scope (conf=%d, known_netblocks=%d) for %v\n", conf, len(nblocks), ip.Address.String())
		for _, nb := range nblocks {
			if nb.CIDR.Contains(ip.Address) {
				fmt.Fprintf(os.Stderr, "DEBUG protocol_probes MATCHING NETBLOCK EXISTS BUT WASN'T MATCHED: %v contains %v\n", nb.CIDR, ip.Address)
			}
		}
		return nil
	}

	ports := e.Session.Config().Scope.Ports
	if len(ports) == 0 {
		fmt.Fprintf(os.Stderr, "DEBUG protocol_probes EXIT zero-ports for %v\n", ip.Address.String())
		return nil
	}
	fmt.Fprintf(os.Stderr, "DEBUG protocol_probes ports=%d for %v\n", len(ports), ip.Address.String())

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), pp.name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG protocol_probes EXIT ttl-error (%v) for %v\n", err, ip.Address.String())
		return err
	}
	fmt.Fprintf(os.Stderr, "DEBUG protocol_probes since=%v for %v\n", since, ip.Address.String())

	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, pp.source, since) {
		fmt.Fprintf(os.Stderr, "DEBUG protocol_probes EXIT already-monitored for %v\n", ip.Address.String())
		return nil
	}

	fmt.Fprintf(os.Stderr, "DEBUG protocol_probes REACHED probe loop for %v\n", ip.Address.String())

	addr := ip.Address.String()
	dial := selectDialer(e)
	for _, port := range ports {
		pp.probeOnePort(e, dial, addr, port)
	}

	fmt.Fprintf(os.Stderr, "DEBUG protocol_probes COMPLETED for %v\n", ip.Address.String())
	support.MarkAssetMonitored(e.Session, e.Entity, pp.source)
	return nil
}

// probeOnePort peeks a single port, classifies whatever (if anything)
// arrived, and routes to the appropriate next step. Errors from any
// individual port are logged and otherwise swallowed - one unreachable
// or misbehaving port should never prevent the remaining configured
// ports from being tried.
func (pp *protocolProbes) probeOnePort(e *et.Event, dial amassnet.DialContext, addr string, port int) {
	target := net.JoinHostPort(addr, strconv.Itoa(port))

	result := PeekBanner(e.Session.Ctx(), dial, target, PeekTimeout)
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
		if err := HarvestCertificate(e, dial, e.Entity, target, port, PeekTimeout); err != nil {
			// TEMPORARY DIAGNOSTIC - remove once the missing-certificate
			// investigation is resolved. Writes directly to stderr,
			// bypassing the same log-visibility gap confirmed for
			// "Plugin started" and the association rationale earlier -
			// pp.log.Warn on the line below has never once shown up in
			// either docker logs engine or docker logs syslog.
			fmt.Fprintf(os.Stderr, "DEBUG protocol_probes cert-harvest-failed target=%v error=%v\n", target, err)
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
