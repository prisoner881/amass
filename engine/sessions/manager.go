// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

/*
 * Amass Engine allow users to create multiple sessions.
 * Each session has its own configuration.
 * The session manager is responsible for managing all sessions,
 * it's a singleton object and it's thread-safe.
 */

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

type manager struct {
	sync.RWMutex
	logger       *slog.Logger
	registry     et.Registry
	sessions     map[uuid.UUID]et.Session
	shutdownHook func(et.Session)
	endWork      sync.Map
	endWorkDone  sync.Map
}

// NewManager: creates a new session storage.
func NewManager(l *slog.Logger, reg et.Registry) et.SessionManager {
	return &manager{
		logger:   l,
		registry: reg,
		sessions: make(map[uuid.UUID]et.Session),
	}
}

func (r *manager) NewSession(cfg *config.Config) (et.Session, error) {
	s, err := CreateSession(r, r.registry, cfg)
	if err == nil {
		err = r.AddSession(s)

		if err == nil {
			return s, nil
		}
	}
	return nil, err
}

// Add: adds a session to a session storage after checking the session config.
func (r *manager) AddSession(s et.Session) error {
	if s == nil {
		return errors.New("the provided session is nil")
	}

	r.Lock()
	if sess, ok := s.(*Session); ok {
		r.sessions[sess.id] = sess
	}
	r.Unlock()

	// TODO: Need to add the session config checks here (using the Registry)
	return nil
}

func (r *manager) SetShutdownHook(fn func(et.Session)) {
	r.Lock()
	r.shutdownHook = fn
	r.Unlock()
}

// CancelSession: cancels a session in a session storage.
func (r *manager) CancelSession(id uuid.UUID) {
	s := r.GetSession(id)
	if s == nil {
		return
	}

	// The session-end hook is deliberately NOT run here. CancelSession is
	// the path taken by TerminateSession, Ctrl-C in the CLI and engine
	// shutdown; an operator stopping a run expects work to stop, not for
	// owned-netblock fills and the Protocol-Probes sweep to start (and
	// block Kill() for hours). The hook runs only through RunEndWork. If
	// RunEndWork is still in progress, Kill() below makes the hook's
	// s.Done() checks return early.
	s.Kill()

	r.Lock()
	delete(r.sessions, id)
	r.Unlock()

	time.Sleep(10 * time.Second)
	if backlog := s.Backlog(); backlog != nil {
		if err := backlog.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the backlog for session %s: %v", id, err))
		}
	}
	if dir := s.TmpDir(); dir != "" {
		_ = os.RemoveAll(dir)
	}
	if db := s.DB(); db != nil {
		if err := db.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the database for session %s: %v", id, err))
		}
	}
	s.PubSub().Close()
}

// RunEndWork executes the session-end hook without destroying the
// session. Enum uses this after first-pass idle so fill/sweep work
// shows up in /stats; a later idle is the real completion signal.
// Only the first call for a session runs the hook; later calls (repeated
// POST /end-work requests, CLI retries) return immediately instead of
// parking a goroutine for the hook's full duration.
func (r *manager) RunEndWork(id uuid.UUID) {
	s := r.GetSession(id)
	if s == nil {
		return
	}
	if _, started := r.endWork.LoadOrStore(id, true); started {
		return
	}

	r.RLock()
	hook := r.shutdownHook
	r.RUnlock()
	if hook != nil {
		hook(s)
	}
	r.endWorkDone.Store(id, true)
}

func (r *manager) EndWorkDone(id uuid.UUID) bool {
	v, ok := r.endWorkDone.Load(id)
	return ok && v.(bool)
}

func (r *manager) GetSessions() []et.Session {
	r.RLock()
	defer r.RUnlock()

	sessions := make([]et.Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

// GetSession: returns a session from a session storage.
func (r *manager) GetSession(id uuid.UUID) et.Session {
	r.RLock()
	defer r.RUnlock()

	if s, found := r.sessions[id]; found {
		return s
	}
	return nil
}

func (r *manager) NumOfSessions() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.sessions)
}

// Shutdown: cleans all sessions from a session storage and shutdown the session storage.
func (r *manager) Shutdown() {
	var list []uuid.UUID

	r.Lock()
	for k := range r.sessions {
		list = append(list, k)
	}
	r.Unlock()

	var wg sync.WaitGroup
	for _, id := range list {
		wg.Add(1)
		go func(id uuid.UUID, wg *sync.WaitGroup) {
			defer wg.Done()

			r.CancelSession(id)
		}(id, &wg)
	}
	wg.Wait()
}
