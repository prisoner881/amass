// Copyright (c) by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	_ "net/http/pprof"

	"github.com/owasp-amass/amass/v5/engine/api/server"
	"github.com/owasp-amass/amass/v5/engine/dispatcher"
	"github.com/owasp-amass/amass/v5/engine/plugins"
	"github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/protocol_probes"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/registry"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

type Engine struct {
	Log        *slog.Logger
	Dispatcher et.Dispatcher
	Registry   et.Registry
	Manager    et.SessionManager
	Server     *server.Server
}

func NewEngine(l *slog.Logger) (*Engine, error) {
	go func() {
		_ = http.ListenAndServe("127.0.0.1:6060", nil)
	}()

	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	logBuildInfo(l)

	reg := registry.NewRegistry(l)
	mgr := sessions.NewManager(l, reg)
	if mgr == nil {
		return nil, errors.New("failed to create the session manager")
	}

	dis := dispatcher.NewDispatcher(l, reg, mgr)
	if err := plugins.LoadAndStartPlugins(reg); err != nil {
		return nil, err
	}

	mgr.SetShutdownHook(func(s et.Session) {
		support.FinishOwnedNetblockFills(s, dis)
		protocol_probes.SweepMissedIPs(s, dis)
	})

	srv, err := server.NewServer(l, dis, mgr)
	if err != nil || srv == nil {
		dis.Shutdown()
		mgr.Shutdown()
		return nil, errors.New("failed to create the API server")
	}

	ch := make(chan error, 1)
	go func(errch chan error) { errch <- srv.Start() }(ch)

	t := time.NewTimer(3 * time.Second)
	defer t.Stop()

	select {
	case err := <-ch:
		if err != nil {
			_ = srv.Shutdown()
			dis.Shutdown()
			mgr.Shutdown()
			return nil, err
		}
	case <-t.C:
		// If the server does not return an error within 3 seconds, we assume it started successfully
	}

	return &Engine{
		Log:        l,
		Dispatcher: dis,
		Registry:   reg,
		Manager:    mgr,
		Server:     srv,
	}, nil
}

// depVersions lists the module paths reported in the engine startup
// build-info banner. Add a module here to surface its compiled-in
// version at boot. Versions come from runtime/debug.ReadBuildInfo(),
// which reads what is actually baked into this binary, so the banner
// cannot drift out of sync with go.mod the way a hardcoded string would.
var depVersions = []string{
	"github.com/projectdiscovery/wappalyzergo",
	"github.com/owasp-amass/resolve",
	"github.com/owasp-amass/asset-db",
	"github.com/owasp-amass/open-asset-model",
}

// logBuildInfo emits a single startup line recording this engine's own
// build revision and the versions of a few key dependencies, read from
// the binary's embedded build info. It answers "is this running engine
// actually the code and dependencies I think it is?" without needing to
// inspect go.mod or the image. Best-effort: if build info is
// unavailable (e.g. built without module info), it logs what it can.
func logBuildInfo(l *slog.Logger) {
	attrs := []any{}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		l.Info("engine build info unavailable")
		return
	}

	// Amass' own version and VCS revision, when present.
	if bi.Main.Version != "" {
		attrs = append(attrs, "amass_version", bi.Main.Version)
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			attrs = append(attrs, "vcs_revision", s.Value)
		case "vcs.modified":
			attrs = append(attrs, "vcs_modified", s.Value)
		}
	}

	// Selected dependency versions.
	want := make(map[string]bool, len(depVersions))
	for _, p := range depVersions {
		want[p] = true
	}
	for _, dep := range bi.Deps {
		if want[dep.Path] {
			attrs = append(attrs, dep.Path, dep.Version)
		}
	}

	l.Info("engine build info", attrs...)
}

func (e *Engine) Shutdown() {
	_ = e.Server.Shutdown()
	// Sweep while the dispatcher pump can still claim resubmitted IPs.
	// CancelSession (TerminateSession) also runs the hook; a second
	// pass is a no-op once Protocol-Probes has marked the misses.
	for _, s := range e.Manager.GetSessions() {
		support.FinishOwnedNetblockFills(s, e.Dispatcher)
		protocol_probes.SweepMissedIPs(s, e.Dispatcher)
	}
	e.Dispatcher.Shutdown()
	e.Manager.Shutdown()
}
