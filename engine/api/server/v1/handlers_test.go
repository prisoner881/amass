// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// fakeDB stores nothing: lookups always miss, and CreateAsset fails, panics
// or succeeds according to the asset's key.
type fakeDB struct {
	repository.Repository
	mu     sync.Mutex
	nextID int
}

func (f *fakeDB) FindEntitiesByContent(context.Context, oam.AssetType, time.Time, int, dbt.ContentFilters) ([]*dbt.Entity, error) {
	return nil, errors.New("no entities found")
}

func (f *fakeDB) CreateAsset(_ context.Context, a oam.Asset) (*dbt.Entity, error) {
	switch {
	case strings.HasPrefix(a.Key(), "reject."):
		return nil, errors.New("the database rejected the asset")
	case strings.HasPrefix(a.Key(), "panic."):
		panic("simulated failure")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	return &dbt.Entity{ID: strconv.Itoa(f.nextID), Asset: a}, nil
}

type fakeDispatcher struct{ et.Dispatcher }

func (fakeDispatcher) DispatchEvent(*et.Event) error { return nil }

type fakeSession struct {
	et.Session
	id uuid.UUID
	db *fakeDB
	ps *pubsub.Logger
}

func (s *fakeSession) ID() uuid.UUID             { return s.id }
func (s *fakeSession) DB() repository.Repository { return s.db }
func (s *fakeSession) PubSub() *pubsub.Logger    { return s.ps }

type fakeManager struct {
	et.SessionManager
	sess *fakeSession
}

func (m *fakeManager) GetSession(id uuid.UUID) et.Session {
	if m.sess != nil && id == m.sess.id {
		return m.sess
	}
	return nil
}

func newTestHandlers() (*V1Handlers, *fakeSession) {
	sess := &fakeSession{id: uuid.New(), db: &fakeDB{}, ps: pubsub.NewLogger()}
	return &V1Handlers{ctx: context.Background(), dis: fakeDispatcher{}, mgr: &fakeManager{sess: sess}}, sess
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var e ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("response is not an error object: %q", rec.Body.String())
	}
	return e
}

// A session configuration without a scope used to panic during session
// creation, so the client got no response at all.
func TestCreateSessionRequiresScope(t *testing.T) {
	v, _ := newTestHandlers()
	for _, body := range []string{`{}`, `{"scope":null}`, `{"active":false}`} {
		rec := httptest.NewRecorder()
		v.CreateSessionHandler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got status %d, want 400", body, rec.Code)
		}
		if e := decodeError(t, rec); e.Error != "invalid configuration" || e.Details != "scope is required" {
			t.Fatalf("%s: got %+v", body, e)
		}
	}
}

func addAsset(v *V1Handlers, token uuid.UUID, atype, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"session_token": token.String(), "asset_type": atype})
	rec := httptest.NewRecorder()
	v.AddAssetTypedHandler(rec, r)
	return rec
}

func addAssetsBulk(v *V1Handlers, token uuid.UUID, atype, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"session_token": token.String(), "asset_type": atype})
	rec := httptest.NewRecorder()
	v.AddAssetsBulkHandler(rec, r)
	return rec
}

// An asset with no identifying value is refused with a 400 before it reaches
// the database. It used to reach the database, fail, and panic.
func TestAddAssetWithoutIdentifyingValue(t *testing.T) {
	v, sess := newTestHandlers()
	for _, body := range []string{`{"bogus":1}`, `{"name":""}`, `{"name":"   "}`} {
		rec := addAsset(v, sess.id, "fqdn", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got status %d, want 400", body, rec.Code)
		}
		if e := decodeError(t, rec); e.Error != "invalid asset object" {
			t.Fatalf("%s: got %+v", body, e)
		}
	}
}

// When the database rejects an asset, the client gets a 500 with the reason
// instead of a dropped connection.
func TestAddAssetDatabaseRejection(t *testing.T) {
	v, sess := newTestHandlers()
	rec := addAsset(v, sess.id, "fqdn", `{"name":"reject.example.com"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != "failed to submit the asset" || !strings.Contains(e.Details, "rejected") {
		t.Fatalf("got %+v", e)
	}

	rec = addAsset(v, sess.id, "fqdn", `{"name":"ok.example.com"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid asset: got status %d, want 200", rec.Code)
	}
}

// One bad item in a bulk request used to crash the whole engine, because the
// failure happened in a goroutine outside the HTTP server's panic recovery.
// Now it is counted as failed and the rest are stored.
func TestBulkAddCountsFailuresInsteadOfCrashing(t *testing.T) {
	v, sess := newTestHandlers()
	body := `{"items":[
		{"name":"a.example.com"},
		{"name":"reject.example.com"},
		{"name":"panic.example.com"},
		{"name":"b.example.com"},
		{"bogus":1}
	]}`
	rec := addAssetsBulk(v, sess.id, "fqdn", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp BulkAddAssetsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// {"bogus":1} has no identifying value, so it is not ingested.
	if resp.Ingested != 4 || resp.Stored != 2 || resp.Failed != 2 {
		t.Fatalf("got %+v, want ingested 4, stored 2, failed 2", resp)
	}
}

func TestPutAssetReturnsDatabaseError(t *testing.T) {
	v, sess := newTestHandlers()
	id, err := v.PutAsset(context.Background(), sess, &oamdns.FQDN{Name: "reject.example.com"})
	if err == nil || id != "" {
		t.Fatalf("got (%q, %v), want an error and no ID", id, err)
	}
}

// A log-stream client that goes away is unsubscribed at once, so the engine
// stops queueing messages for it.
func TestWSLogsUnsubscribesDisconnectedClient(t *testing.T) {
	v, sess := newTestHandlers()
	defer sess.ps.Close()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/sessions/{session_token}/ws/logs", v.WSLogsHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/sessions/" + sess.id.String() + "/ws/logs"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitForSubscribers(t, sess.ps, 1)

	sess.ps.Publish(`{"msg":"hello"}`)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, msg, err := conn.ReadMessage(); err != nil || string(msg) != `{"msg":"hello"}` {
		t.Fatalf("got (%q, %v)", msg, err)
	}

	_ = conn.Close()
	waitForSubscribers(t, sess.ps, 0)
}

// When the session's log stream closes (the session ended), the client gets a
// close frame.
func TestWSLogsClosesWhenSessionEnds(t *testing.T) {
	v, sess := newTestHandlers()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/sessions/{session_token}/ws/logs", v.WSLogsHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/sessions/" + sess.id.String() + "/ws/logs"
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	waitForSubscribers(t, sess.ps, 1)

	sess.ps.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = conn.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("got %v, want a normal close frame", err)
	}
}

func waitForSubscribers(t *testing.T, ps *pubsub.Logger, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for ps.Subscribers() != want {
		if time.Now().After(deadline) {
			t.Fatalf("got %d subscribers, want %d", ps.Subscribers(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
