// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// Prospeo finds the work email addresses of people employed at a scope
// domain, using the current Prospeo REST API (https://prospeo.io/api-docs).
// The API has no domain-to-emails call, so each lookup takes three steps:
//
//  1. Account Information (GET, free): the remaining credit balance.
//  2. Search Person (POST): people whose current employer has the domain as
//     its website. 25 results per page, 1 credit per page that returns at
//     least one person; a page already paid for in the last 30 days is free.
//     Search results never contain emails.
//  3. Bulk Enrich Person (POST): reveal the verified email of up to 50 of
//     those people per request, by person_id. 1 credit per verified email
//     found (only_verified_email, no mobile); nothing for a person without
//     one, and nothing to re-enrich a person within 90 days.
//
// Spending is bounded per domain by two datasources.yaml options on the
// Prospeo entry:
//
//	max_emails_per_domain  people enriched per domain (default 25; 0 turns
//	                       the plugin off)
//	min_remaining_credits  credits never spent (default 0)
//
// A domain therefore costs at most ceil(max/25) search credits plus max
// enrichment credits, and nothing is spent once the balance reaches the
// reserve. A lookup is marked monitored only when every request succeeded
// (see support.HTTPLookupFailure); a failed one is retried next session.
type Prospeo struct {
	name        string
	baseurl     string
	log         *slog.Logger
	searchLimit *rate.Limiter
	enrichLimit *rate.Limiter
	source      *et.Source
}

const (
	prospeoPageSize          = 25
	prospeoBulkMax           = 50
	prospeoDefaultMaxEmails  = 25
	prospeoDefaultMinCredits = 0
	prospeoTimeout           = 30 * time.Second
)

func NewProspeo() et.Plugin {
	return &Prospeo{
		name:    "Prospeo",
		baseurl: "https://api.prospeo.io",
		// The Starter plan allows 1 search and 5 enrichment requests per
		// second; Account Information is counted with enrichment.
		searchLimit: rate.NewLimiter(rate.Every(time.Second), 1),
		enrichLimit: rate.NewLimiter(rate.Every(500*time.Millisecond), 1),
		source: &et.Source{
			Name:       "Prospeo",
			Confidence: 80,
		},
	}
}

func (p *Prospeo) Name() string {
	return p.name
}

func (p *Prospeo) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	name := p.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         name,
		Position:     29,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Identifier)},
		EventType:    oam.FQDN,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *Prospeo) Stop() {
	p.log.Info("Plugin stopped")
}

func (p *Prospeo) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	// No key, or a budget of zero: nothing to do, and nothing to mark.
	ds := e.Session.Config().GetDataSourceConfig(p.name)
	key := prospeoKey(ds)
	if key == "" || ds.IntOption("max_emails_per_domain", prospeoDefaultMaxEmails) <= 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Identifier), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}

	emails, completed := p.query(e, fqdn.Name, key, ds)
	if completed {
		support.MarkAssetMonitored(e.Session, e.Entity, p.source)
	}
	if len(emails) > 0 {
		p.process(e, emails)
	}
	return nil
}

func prospeoKey(ds *config.DataSource) string {
	if ds == nil {
		return ""
	}
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			return cr.Apikey
		}
	}
	return ""
}

// prospeoBudget splits the credits available above the reserve between
// search pages and enrichments: the pages needed to find up to maxEmails
// people are paid first, and the rest bounds the enrichments. It returns
// the number of people to enrich, 0 when nothing can be spent.
func prospeoBudget(remaining, reserve, maxEmails int) int {
	avail := remaining - reserve
	people := min(maxEmails, avail)
	if people <= 0 {
		return 0
	}
	pages := (people + prospeoPageSize - 1) / prospeoPageSize
	return max(min(people, avail-pages), 0)
}

// query returns the stored email entities for domain, and whether every
// request succeeded.
func (p *Prospeo) query(e *et.Event, domain, key string, ds *config.DataSource) ([]*dbt.Entity, bool) {
	maxEmails := ds.IntOption("max_emails_per_domain", prospeoDefaultMaxEmails)
	reserve := ds.IntOption("min_remaining_credits", prospeoDefaultMinCredits)

	remaining, reason := p.remainingCredits(e, key)
	if reason != "" {
		p.lookupFailed(e, domain, "account information: "+reason)
		return nil, false
	}
	people := prospeoBudget(remaining, reserve, maxEmails)
	if people == 0 {
		p.lookupFailed(e, domain, fmt.Sprintf("%d credits remaining, reserve is %d", remaining, reserve))
		return nil, false
	}

	ids, searchCost, reason := p.searchPeople(e, domain, key, people)
	if reason != "" {
		p.lookupFailed(e, domain, "search: "+reason)
		return nil, false
	}
	if len(ids) == 0 {
		return nil, true
	}

	emails, enrichCost, reason := p.enrich(e, key, ids)
	stored := p.store(e, emails)
	p.log.Info("Prospeo lookup", "domain", domain, "people", len(ids), "emails", len(emails),
		"credits_spent", searchCost+enrichCost, "credits_before", remaining)
	if reason != "" {
		p.lookupFailed(e, domain, "enrich: "+reason)
		return stored, false
	}
	return stored, true
}

func (p *Prospeo) lookupFailed(e *et.Event, domain, reason string) {
	if e.Session.Ctx().Err() == nil {
		support.LogLookupFailure(p.log, p.name, domain, reason)
	}
}

// call sends a JSON request (GET when body is nil, POST otherwise) and
// decodes the reply into out. It returns why the request failed, or "".
func (p *Prospeo) call(e *et.Event, limiter *rate.Limiter, path, key string, body, out any) string {
	if err := limiter.Wait(e.Session.Ctx()); err != nil {
		return err.Error()
	}

	req := &amasshttp.Request{
		Method: "GET",
		URL:    p.baseurl + path,
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}, "X-KEY": []string{key}},
	}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err.Error()
		}
		req.Method = "POST"
		req.Body = string(b)
	}

	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), prospeoTimeout)
	defer cancel()
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, req)
	e.Session.NetSem().Release()

	// Prospeo reports errors as {"error": true, "error_code": "..."}, mostly
	// with status 400.
	var status struct {
		Error     bool   `json:"error"`
		ErrorCode string `json:"error_code"`
	}
	if err == nil && resp != nil && resp.Body != "" {
		_ = json.Unmarshal([]byte(resp.Body), &status)
	}
	if status.ErrorCode != "" {
		return fmt.Sprintf("HTTP %d %s", resp.StatusCode, status.ErrorCode)
	}
	if reason := support.HTTPLookupFailure(resp, err); reason != "" {
		return reason
	}
	if status.Error {
		return "error without an error_code"
	}
	if err := json.Unmarshal([]byte(resp.Body), out); err != nil {
		return "undecodable response: " + err.Error()
	}
	return ""
}

func (p *Prospeo) remainingCredits(e *et.Event, key string) (int, string) {
	var r struct {
		Response struct {
			RemainingCredits int `json:"remaining_credits"`
		} `json:"response"`
	}
	if reason := p.call(e, p.enrichLimit, "/account-information", key, nil, &r); reason != "" {
		return 0, reason
	}
	return r.Response.RemainingCredits, ""
}

type prospeoSearchRequest struct {
	Page    int `json:"page"`
	Filters struct {
		Company struct {
			Websites struct {
				Include []string `json:"include"`
			} `json:"websites"`
		} `json:"company"`
	} `json:"filters"`
}

type prospeoSearchResponse struct {
	Free    bool `json:"free"`
	Results []struct {
		Person struct {
			PersonID string `json:"person_id"`
		} `json:"person"`
	} `json:"results"`
	Pagination struct {
		CurrentPage int `json:"current_page"`
		TotalPage   int `json:"total_page"`
	} `json:"pagination"`
}

// searchPeople returns the person_id of up to limit people whose current
// employer has domain as its website, and the credits spent. A search with
// no matches is an answer, not a failure.
func (p *Prospeo) searchPeople(e *et.Event, domain, key string, limit int) ([]string, int, string) {
	var ids []string
	var cost int
	seen := make(map[string]struct{})

	for page := 1; len(ids) < limit; page++ {
		var req prospeoSearchRequest
		req.Page = page
		req.Filters.Company.Websites.Include = []string{domain}

		var r prospeoSearchResponse
		if reason := p.call(e, p.searchLimit, "/search-person", key, &req, &r); reason != "" {
			if strings.HasSuffix(reason, " NO_RESULTS") {
				break
			}
			return ids, cost, reason
		}
		if len(r.Results) > 0 && !r.Free {
			cost++
		}

		for _, res := range r.Results {
			id := res.Person.PersonID
			if id == "" {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
			if len(ids) == limit {
				break
			}
		}
		if len(r.Results) == 0 || r.Pagination.CurrentPage >= r.Pagination.TotalPage {
			break
		}
	}
	return ids, cost, ""
}

type prospeoBulkRecord struct {
	Identifier string `json:"identifier"`
	PersonID   string `json:"person_id"`
}

type prospeoBulkRequest struct {
	OnlyVerifiedEmail bool                `json:"only_verified_email"`
	EnrichMobile      bool                `json:"enrich_mobile"`
	Data              []prospeoBulkRecord `json:"data"`
}

type prospeoBulkResponse struct {
	TotalCost int `json:"total_cost"`
	Matched   []struct {
		Person struct {
			Email struct {
				Revealed bool   `json:"revealed"`
				Email    string `json:"email"`
			} `json:"email"`
		} `json:"person"`
	} `json:"matched"`
}

// enrich reveals the verified emails of the given people, 50 per request.
// It returns the emails received, the credits spent, and why a request
// failed, if one did; emails from earlier requests are still returned.
func (p *Prospeo) enrich(e *et.Event, key string, ids []string) ([]string, int, string) {
	var emails []string
	var cost int

	for start := 0; start < len(ids); start += prospeoBulkMax {
		req := prospeoBulkRequest{OnlyVerifiedEmail: true}
		for i, id := range ids[start:min(start+prospeoBulkMax, len(ids))] {
			req.Data = append(req.Data, prospeoBulkRecord{Identifier: strconv.Itoa(start + i), PersonID: id})
		}

		var r prospeoBulkResponse
		if reason := p.call(e, p.enrichLimit, "/bulk-enrich-person", key, &req, &r); reason != "" {
			return emails, cost, reason
		}
		cost += r.TotalCost

		for _, m := range r.Matched {
			addr := strings.ToLower(strings.TrimSpace(m.Person.Email.Email))
			// Unrevealed addresses come back masked ("j*****@example.com").
			if !m.Person.Email.Revealed || !strings.Contains(addr, "@") || strings.Contains(addr, "*") {
				continue
			}
			emails = append(emails, addr)
		}
	}
	return emails, cost, ""
}

func (p *Prospeo) store(e *et.Event, emails []string) []*dbt.Entity {
	return support.StoreEmailsWithSource(e.Session, emails, p.source, p.name, p.name+"-Handler")
}

func (p *Prospeo) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessEmailsWithSource(e, assets, p.source)
}
