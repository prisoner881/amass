// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
)

// hookTestSession is the minimum et.Session the manager touches when a
// session is cancelled.
type hookTestSession struct {
	et.Session
	id     uuid.UUID
	killed atomic.Bool
	ps     *pubsub.Logger
}

func (s *hookTestSession) ID() uuid.UUID             { return s.id }
func (s *hookTestSession) Kill()                     { s.killed.Store(true) }
func (s *hookTestSession) Done() bool                { return s.killed.Load() }
func (s *hookTestSession) Backlog() et.Backlog       { return nil }
func (s *hookTestSession) TmpDir() string            { return "" }
func (s *hookTestSession) DB() repository.Repository { return nil }
func (s *hookTestSession) PubSub() *pubsub.Logger    { return s.ps }
func (s *hookTestSession) Log() *slog.Logger         { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newHookTestManager(t *testing.T) (*manager, *hookTestSession) {
	t.Helper()
	mgr := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)), nil).(*manager)
	s := &hookTestSession{id: uuid.New(), ps: pubsub.NewLogger()}
	mgr.sessions[s.id] = s
	return mgr, s
}

// Cancelling a session (TerminateSession, Ctrl-C, engine shutdown) must
// not start the session-end hook.
func TestCancelSessionDoesNotRunEndWorkHook(t *testing.T) {
	mgr, s := newHookTestManager(t)

	var calls atomic.Int32
	mgr.SetShutdownHook(func(et.Session) { calls.Add(1) })

	// CancelSession sleeps before closing resources; only the part up to
	// Kill() matters here.
	go mgr.CancelSession(s.id)
	deadline := time.Now().Add(5 * time.Second)
	for !s.killed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !s.killed.Load() {
		t.Fatal("CancelSession did not kill the session")
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("CancelSession ran the session-end hook %d times, want 0", n)
	}
}

// Only the first RunEndWork runs the hook. Later calls, including ones
// made while the hook is still running, return immediately.
func TestRunEndWorkRunsHookOnceAndDoesNotBlock(t *testing.T) {
	mgr, s := newHookTestManager(t)

	release := make(chan struct{})
	var calls atomic.Int32
	mgr.SetShutdownHook(func(et.Session) {
		calls.Add(1)
		<-release
	})

	var first sync.WaitGroup
	first.Add(1)
	go func() {
		defer first.Done()
		mgr.RunEndWork(s.id)
	}()
	for calls.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	returned := make(chan struct{})
	go func() {
		mgr.RunEndWork(s.id)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("a second RunEndWork blocked while the hook was running")
	}
	if mgr.EndWorkDone(s.id) {
		t.Error("EndWorkDone reported true before the hook finished")
	}

	close(release)
	first.Wait()
	if !mgr.EndWorkDone(s.id) {
		t.Error("EndWorkDone reported false after the hook finished")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("hook ran %d times, want 1", n)
	}
}
