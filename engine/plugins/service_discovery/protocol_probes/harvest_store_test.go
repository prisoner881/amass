// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// harvestTestSession satisfies et.Session for HarvestCertificate, which
// only calls Ctx, DB and Log on this path.
type harvestTestSession struct {
	et.Session
	db repository.Repository
}

func (s *harvestTestSession) Ctx() context.Context      { return context.Background() }
func (s *harvestTestSession) DB() repository.Repository { return s.db }
func (s *harvestTestSession) Log() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type recordingDispatcher struct {
	et.Dispatcher
	mu     sync.Mutex
	events []*et.Event
}

func (d *recordingDispatcher) DispatchEvent(e *et.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, e)
	return nil
}

func (d *recordingDispatcher) dispatched(atype oam.AssetType) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	var n int
	for _, e := range d.events {
		if e.Entity != nil && e.Entity.Asset.AssetType() == atype {
			n++
		}
	}
	return n
}

func newHarvestTestEvent(t *testing.T) (*et.Event, *recordingDispatcher) {
	t.Helper()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatalf("failed to open the test asset database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ipEnt, err := db.CreateAsset(context.Background(), &oamnet.IPAddress{
		Address: netip.MustParseAddr("127.0.0.1"),
		Type:    "IPv4",
	})
	if err != nil {
		t.Fatalf("failed to create the IPAddress entity: %v", err)
	}

	d := &recordingDispatcher{}
	return &et.Event{
		Entity:     ipEnt,
		Session:    &harvestTestSession{db: db},
		Dispatcher: d,
	}, d
}

func findService(t *testing.T, e *et.Event, port int) *dbt.Entity {
	t.Helper()
	id := support.ServiceWithIdentifier("127.0.0.1", "tcp", port).ID
	found, err := e.Session.DB().FindEntitiesByContent(context.Background(), oam.Service, time.Time{}, 1,
		dbt.ContentFilters{"unique_id": id})
	if err != nil || len(found) == 0 {
		return nil
	}
	return found[0]
}

func listenerPort(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad listener address %q: %v", addr, err)
	}
	port, _ := strconv.Atoi(p)
	return port
}

// A silent port that is not TLS must not produce a Service.
func TestHarvestCertificate_FailedHandshakeCreatesNoService(t *testing.T) {
	e, d := newHarvestTestEvent(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start plain listener: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(300 * time.Millisecond)
	}()
	port := listenerPort(t, ln.Addr().String())

	if err := HarvestCertificate(e, nil, e.Entity, "127.0.0.1", port, time.Second); err == nil {
		t.Fatal("expected a handshake error against a non-TLS port")
	}
	if svc := findService(t, e, port); svc != nil {
		t.Errorf("a Service was created for a failed handshake: %+v", svc.Asset)
	}
	if n := d.dispatched(oam.Service); n != 0 {
		t.Errorf("dispatched %d Service events, want 0", n)
	}
}

// A successful handshake creates the "tls" Service, links it with the
// same named PortRelation http_probes uses, stores the certificate and
// dispatches the Service.
func TestHarvestCertificate_SuccessStoresAndDispatchesService(t *testing.T) {
	e, d := newHarvestTestEvent(t)

	addr := startTLSServer(t, generateSelfSignedCert(t, "test.example.com"))
	port := listenerPort(t, addr)

	if err := HarvestCertificate(e, nil, e.Entity, "127.0.0.1", port, 2*time.Second); err != nil {
		t.Fatalf("unexpected harvest error: %v", err)
	}

	svcEnt := findService(t, e, port)
	if svcEnt == nil {
		t.Fatal("no Service was created after a successful handshake")
	}
	if svc := svcEnt.Asset.(*oamplat.Service); svc.Type != "tls" {
		t.Errorf("Service type = %q, want %q", svc.Type, "tls")
	}

	ctx := context.Background()
	// Query without a label: SQLite stores the relation's own label,
	// while Postgres stores every PortRelation under "port" and keeps
	// the name only in the edge content.
	label := fmt.Sprintf("tcp_port_%d", port)
	edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, time.Time{})
	if err != nil || len(edges) != 1 {
		t.Fatalf("IP has %d outgoing edges (err %v), want exactly 1 port edge", len(edges), err)
	}
	if rel, ok := edges[0].Relation.(*oamgen.PortRelation); !ok || rel.Name != label || rel.PortNumber != port {
		t.Errorf("port edge relation = %+v, want PortRelation %q on port %d", edges[0].Relation, label, port)
	}

	if certs, _ := e.Session.DB().OutgoingEdges(ctx, svcEnt, time.Time{}, "certificate"); len(certs) != 1 {
		t.Errorf("Service has %d certificate edges, want 1", len(certs))
	}
	if n := d.dispatched(oam.Service); n != 1 {
		t.Errorf("dispatched %d Service events, want 1", n)
	}
}

// A Service http_probes already created keeps its type, and its port edge
// keeps its name, when Protocol-Probes reaches the same host:port.
func TestFindOrCreateService_PreservesHTTPProbesService(t *testing.T) {
	e, _ := newHarvestTestEvent(t)
	ctx := context.Background()
	const port = 8443
	label := fmt.Sprintf("tcp_port_%d", port)

	serv := support.ServiceWithIdentifier("127.0.0.1", "tcp", port)
	serv.Type = "web-service"
	serv.Output = "<html></html>"
	serv.OutputLen = len(serv.Output)
	httpSvc, err := e.Session.DB().CreateAsset(ctx, serv)
	if err != nil {
		t.Fatalf("failed to seed the http_probes Service: %v", err)
	}
	if _, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.PortRelation{Name: label, PortNumber: port, Protocol: "tcp"},
		FromEntity: e.Entity,
		ToEntity:   httpSvc,
	}); err != nil {
		t.Fatalf("failed to seed the http_probes port edge: %v", err)
	}

	svcEnt, _, err := FindOrCreateService(e, e.Entity, "127.0.0.1", port, "tls", "")
	if err != nil {
		t.Fatalf("FindOrCreateService failed: %v", err)
	}
	if svcEnt.ID != httpSvc.ID {
		t.Errorf("got Service %s, want the existing %s", svcEnt.ID, httpSvc.ID)
	}
	if got := findService(t, e, port).Asset.(*oamplat.Service).Type; got != "web-service" {
		t.Errorf("Service type = %q, want %q", got, "web-service")
	}

	edges, err := e.Session.DB().OutgoingEdges(ctx, e.Entity, time.Time{})
	if err != nil || len(edges) != 1 {
		t.Fatalf("IP has %d outgoing edges (err %v), want exactly 1 port edge", len(edges), err)
	}
	if rel, ok := edges[0].Relation.(*oamgen.PortRelation); !ok || rel.Name != label {
		t.Errorf("port edge relation = %+v, want name %q", edges[0].Relation, label)
	}
}
