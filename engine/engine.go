// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
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
