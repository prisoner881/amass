// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	general "github.com/owasp-amass/open-asset-model/general"
)

func TestProspeoBudget(t *testing.T) {
	cases := []struct{ remaining, reserve, max, want int }{
		{100, 0, 25, 25},  // 1 search credit + 25 enrichments fit
		{26, 0, 25, 25},   // exactly enough
		{25, 0, 25, 24},   // the search page is paid first
		{10, 0, 25, 9},    // a small balance bounds the enrichments
		{110, 100, 25, 9}, // the reserve is never spent
		{100, 100, 25, 0}, // at the reserve: nothing
		{1, 0, 25, 0},     // one credit only covers a search page
		{0, 0, 25, 0},
		{1000, 0, 60, 60}, // 3 pages
	}
	for _, c := range cases {
		if got := prospeoBudget(c.remaining, c.reserve, c.max); got != c.want {
			t.Errorf("prospeoBudget(%d, %d, %d) = %d, want %d", c.remaining, c.reserve, c.max, got, c.want)
		}
	}
}

type prospeoCall struct {
	method, path, key string
	body              map[string]any
}

// prospeoServer answers by request path and records every request.
type prospeoServer struct {
	mu      sync.Mutex
	calls   []prospeoCall
	handler func(path string, body map[string]any) fakeResp
}

func (s *prospeoServer) RoundTrip(req *http.Request) (*http.Response, error) {
	var body map[string]any
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(b, &body)
	}
	s.mu.Lock()
	s.calls = append(s.calls, prospeoCall{req.Method, req.URL.Path, req.Header.Get("X-KEY"), body})
	s.mu.Unlock()

	r := s.handler(req.URL.Path, body)
	return &http.Response{
		StatusCode: r.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

func (s *prospeoServer) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.calls {
		out = append(out, c.method+" "+c.path)
	}
	return out
}

func (s *prospeoServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, c := range s.calls {
		if c.path == path {
			n++
		}
	}
	return n
}

func accountReply(remaining int) fakeResp {
	return ok200(fmt.Sprintf(`{"error":false,"response":{"current_plan":"STARTER","remaining_credits":%d}}`, remaining))
}

// searchReply returns people p<from>..p<to-1> on a page of totalPages.
func searchReply(from, to, page, totalPages int) fakeResp {
	var res []string
	for i := from; i < to; i++ {
		res = append(res, fmt.Sprintf(`{"person":{"person_id":"p%d","email":{"revealed":false,"email":"x*****@example.com"}},"company":{}}`, i))
	}
	return ok200(fmt.Sprintf(`{"error":false,"free":false,"results":[%s],"pagination":{"current_page":%d,"per_page":25,"total_page":%d,"total_count":0}}`,
		strings.Join(res, ","), page, totalPages))
}

// enrichAll reveals an email for every person_id in a bulk request.
func enrichAll(body map[string]any) fakeResp {
	data, _ := body["data"].([]any)
	var matched []string
	for _, d := range data {
		rec := d.(map[string]any)
		matched = append(matched, fmt.Sprintf(`{"identifier":"%s","person":{"email":{"status":"VERIFIED","revealed":true,"email":"%s@example.com"}}}`,
			rec["identifier"], rec["person_id"]))
	}
	return ok200(fmt.Sprintf(`{"error":false,"total_cost":%d,"not_matched":[],"invalid_datapoints":[],"matched":[%s]}`,
		len(matched), strings.Join(matched, ",")))
}

func prospeoError(code string) fakeResp {
	return fakeResp{400, `{"error":true,"error_code":"` + code + `"}`}
}

// newProspeoTest returns the plugin and an example.com event whose requests
// go to srv. A nil options map leaves the defaults; key "" configures no key.
func newProspeoTest(t *testing.T, key string, options map[string]int, srv *prospeoServer) (*Prospeo, *et.Event) {
	t.Helper()
	e, _ := newMarkTestEvent(t, fail(500))
	s := e.Session.(*markTestSession)
	s.clients.General.Transport = srv
	if key != "" {
		s.cfg.DataSrcConfigs.Datasources = append(s.cfg.DataSrcConfigs.Datasources, &config.DataSource{
			Name:    "Prospeo",
			Creds:   map[string]*config.Credentials{"account": {Apikey: key}},
			Options: options,
		})
	}
	p := NewProspeo().(*Prospeo)
	p.log = discardLog()
	return p, e
}

func TestProspeoFindsVerifiedEmails(t *testing.T) {
	srv := &prospeoServer{handler: func(path string, body map[string]any) fakeResp {
		switch path {
		case "/account-information":
			return accountReply(100)
		case "/search-person":
			return searchReply(0, 3, 1, 1)
		case "/bulk-enrich-person":
			// p0 revealed, p1 masked, p2 not matched.
			return ok200(`{"error":false,"total_cost":1,"not_matched":["2"],"matched":[
				{"identifier":"0","person":{"email":{"status":"VERIFIED","revealed":true,"email":"Alice.Smith@Example.com"}}},
				{"identifier":"1","person":{"email":{"status":"VERIFIED","revealed":false,"email":"b*****@example.com"}}}]}`)
		}
		return fail(404)
	}}
	p, e := newProspeoTest(t, "test-key", nil, srv)
	if err := p.check(e); err != nil {
		t.Fatalf("check returned an error: %v", err)
	}

	want := []string{"GET /account-information", "POST /search-person", "POST /bulk-enrich-person"}
	if got := srv.paths(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	for _, c := range srv.calls {
		if c.key != "test-key" {
			t.Errorf("%s %s sent X-KEY %q", c.method, c.path, c.key)
		}
	}

	search := srv.calls[1].body
	if got := fmt.Sprint(search["filters"]); got != "map[company:map[websites:map[include:[example.com]]]]" {
		t.Errorf("search filters = %s", got)
	}
	if search["page"] != float64(1) {
		t.Errorf("search page = %v, want 1", search["page"])
	}

	enrich := srv.calls[2].body
	if enrich["only_verified_email"] != true || enrich["enrich_mobile"] != false {
		t.Errorf("enrich options = %v / %v, want only verified emails and no mobile",
			enrich["only_verified_email"], enrich["enrich_mobile"])
	}
	if data, _ := enrich["data"].([]any); len(data) != 3 || data[0].(map[string]any)["person_id"] != "p0" {
		t.Errorf("enrich data = %v, want the 3 person_ids", enrich["data"])
	}

	if !marked(e, p.source) {
		t.Error("a completed lookup was not marked")
	}
	if !storedEmail(t, e, "alice.smith@example.com") {
		t.Error("the revealed email was not stored")
	}
	if storedEmail(t, e, "b*****@example.com") {
		t.Error("a masked email was stored")
	}
}

func TestProspeoRespectsBudget(t *testing.T) {
	srv := &prospeoServer{handler: func(path string, body map[string]any) fakeResp {
		switch path {
		case "/account-information":
			return accountReply(1000)
		case "/search-person":
			return searchReply(0, 25, 1, 4)
		case "/bulk-enrich-person":
			return enrichAll(body)
		}
		return fail(404)
	}}
	p, e := newProspeoTest(t, "k", map[string]int{"max_emails_per_domain": 2}, srv)
	_ = p.check(e)

	if n := srv.count("/search-person"); n != 1 {
		t.Errorf("made %d search requests for 2 people, want 1", n)
	}
	if data, _ := srv.calls[len(srv.calls)-1].body["data"].([]any); len(data) != 2 {
		t.Errorf("enriched %d people, want max_emails_per_domain = 2", len(data))
	}
}

func TestProspeoPagesAndBatches(t *testing.T) {
	srv := &prospeoServer{handler: func(path string, body map[string]any) fakeResp {
		switch path {
		case "/account-information":
			return accountReply(1000)
		case "/search-person":
			page := int(body["page"].(float64))
			return searchReply((page-1)*25, page*25, page, 4)
		case "/bulk-enrich-person":
			return enrichAll(body)
		}
		return fail(404)
	}}
	p, e := newProspeoTest(t, "k", map[string]int{"max_emails_per_domain": 60}, srv)
	_ = p.check(e)

	if n := srv.count("/search-person"); n != 3 {
		t.Errorf("made %d search requests for 60 people, want 3", n)
	}
	var sizes []int
	for _, c := range srv.calls {
		if c.path == "/bulk-enrich-person" {
			data, _ := c.body["data"].([]any)
			sizes = append(sizes, len(data))
		}
	}
	if fmt.Sprint(sizes) != "[50 10]" {
		t.Errorf("bulk request sizes = %v, want [50 10]", sizes)
	}
	if !marked(e, p.source) || !storedEmail(t, e, "p59@example.com") {
		t.Error("the 60th email was not stored, or the lookup was not marked")
	}
}

func TestProspeoNoResultsIsAnAnswer(t *testing.T) {
	srv := &prospeoServer{handler: func(path string, body map[string]any) fakeResp {
		switch path {
		case "/account-information":
			return accountReply(100)
		case "/search-person":
			return prospeoError("NO_RESULTS")
		}
		return fail(404)
	}}
	p, e := newProspeoTest(t, "k", nil, srv)
	_ = p.check(e)
	if srv.count("/bulk-enrich-person") != 0 {
		t.Error("enriched after a search with no results")
	}
	if !marked(e, p.source) {
		t.Error("a search with no results was not marked")
	}
}

func TestProspeoFailuresAreNotMarked(t *testing.T) {
	cases := []struct {
		name    string
		reserve int
		reply   func(path string, body map[string]any) fakeResp
		// wantPaths are the endpoints the lookup must stop after.
		wantPaths []string
	}{
		{"invalid key", 0, func(path string, _ map[string]any) fakeResp {
			return prospeoError("INVALID_API_KEY")
		}, []string{"GET /account-information"}},
		{"at the reserve", 50, func(path string, _ map[string]any) fakeResp {
			return accountReply(50)
		}, []string{"GET /account-information"}},
		{"search rate limited", 0, func(path string, _ map[string]any) fakeResp {
			if path == "/account-information" {
				return accountReply(100)
			}
			return fakeResp{429, `{"error":true,"error_code":"RATE_LIMITED"}`}
		}, []string{"GET /account-information", "POST /search-person"}},
		{"out of credits while enriching", 0, func(path string, body map[string]any) fakeResp {
			switch path {
			case "/account-information":
				return accountReply(100)
			case "/search-person":
				return searchReply(0, 3, 1, 1)
			}
			return prospeoError("INSUFFICIENT_CREDITS")
		}, []string{"GET /account-information", "POST /search-person", "POST /bulk-enrich-person"}},
		{"service unavailable", 0, func(path string, _ map[string]any) fakeResp {
			if path == "/account-information" {
				return accountReply(100)
			}
			return prospeoError("SERVICE_TEMPORARILY_UNAVAILABLE")
		}, []string{"GET /account-information", "POST /search-person"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := &prospeoServer{handler: c.reply}
			p, e := newProspeoTest(t, "k", map[string]int{"min_remaining_credits": c.reserve}, srv)
			_ = p.check(e)
			if got := srv.paths(); strings.Join(got, ",") != strings.Join(c.wantPaths, ",") {
				t.Errorf("requests = %v, want %v", got, c.wantPaths)
			}
			if marked(e, p.source) {
				t.Error("a failed lookup was marked")
			}
		})
	}
}

func TestProspeoNeedsKeyAndBudget(t *testing.T) {
	for _, c := range []struct {
		name    string
		key     string
		options map[string]int
	}{
		{"no key", "", nil},
		{"budget of zero", "k", map[string]int{"max_emails_per_domain": 0}},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := &prospeoServer{handler: func(string, map[string]any) fakeResp { return accountReply(100) }}
			p, e := newProspeoTest(t, c.key, c.options, srv)
			_ = p.check(e)
			if len(srv.calls) != 0 || marked(e, p.source) {
				t.Errorf("made %d requests, marked = %v; want none", len(srv.calls), marked(e, p.source))
			}
		})
	}
}

func storedEmail(t *testing.T, e *et.Event, addr string) bool {
	t.Helper()
	found, err := e.Session.DB().FindEntitiesByContent(context.Background(), oam.Identifier, time.Time{}, 1,
		dbt.ContentFilters{"unique_id": fmt.Sprintf("%s:%s", general.EmailAddress, addr)})
	return err == nil && len(found) > 0
}
