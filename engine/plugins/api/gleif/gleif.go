// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	"golang.org/x/time/rate"
)

var gleifLimit *rate.Limiter

func init() {
	limit := rate.Every(3 * time.Second)

	gleifLimit = rate.NewLimiter(limit, 1)
}

// ErrGLEIFNotFound is GLEIF's answer that no record matches: a 404, a
// search without results, or a record that is not the one requested. Any
// other error from these functions means GLEIF did not answer (transport
// error, unexpected status, undecodable body), and the lookup is worth
// retrying.
var ErrGLEIFNotFound = errors.New("GLEIF: no matching record")

var (
	gleifBaseURL = "https://api.gleif.org/api/v1"
	// gleifClient replaces amasshttp.DefaultClient when set (tests).
	gleifClient *http.Client
)

// gleifGet fetches one GLEIF API document and returns its body.
func gleifGet(ctx context.Context, u string) (string, error) {
	if err := gleifLimit.Wait(ctx); err != nil {
		return "", err
	}
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	client := gleifClient
	if client == nil {
		client = amasshttp.DefaultClient
	}
	resp, err := amasshttp.RequestWebPage(wctx, client, &amasshttp.Request{URL: u})
	if err == nil && resp != nil && resp.StatusCode == 404 {
		return "", ErrGLEIFNotFound
	}
	if reason := support.HTTPLookupFailure(resp, err); reason != "" {
		return "", errors.New("GLEIF: " + reason)
	}
	return resp.Body, nil
}

// GLEIFSearchFuzzyCompletions performs the fuzzy completion search for the given name.
func GLEIFSearchFuzzyCompletions(ctx context.Context, name string) (*FuzzyCompletionsResponse, error) {
	body, err := gleifGet(ctx, gleifBaseURL+"/fuzzycompletions?field=entity.legalName&q="+url.QueryEscape(name))
	if err != nil {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: failed to obtain the LEI record for %s: %w", name, err)
	}

	var result FuzzyCompletionsResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: failed to unmarshal the LEI record for %s: %s", name, err)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: no results found: %w", ErrGLEIFNotFound)
	}

	return &result, nil
}

// GLEIFGetLEIRecord retrieves the LEI record for the given identifier.
func GLEIFGetLEIRecord(ctx context.Context, id string) (*LEIRecord, error) {
	body, err := gleifGet(ctx, gleifBaseURL+"/lei-records/"+id)
	if err != nil {
		return nil, err
	}

	var result SingleResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, err
	} else if result.Data.Type != "lei-records" || result.Data.ID != id {
		return nil, ErrGLEIFNotFound
	}
	return &result.Data, nil
}

// GLEIFGetDirectParentRecord retrieves the direct parent LEI record for the
// given identifier. ErrGLEIFNotFound means the record has no direct parent.
func GLEIFGetDirectParentRecord(ctx context.Context, id string) (*LEIRecord, error) {
	body, err := gleifGet(ctx, gleifBaseURL+"/lei-records/"+id+"/direct-parent")
	if err != nil {
		return nil, err
	}

	var result SingleResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, err
	} else if result.Data.Type != "lei-records" {
		return nil, ErrGLEIFNotFound
	}
	return &result.Data, nil
}

// GLEIFGetDirectChildrenRecords retrieves the direct children LEI records for
// the given identifier. ErrGLEIFNotFound means the record has no direct
// children; any other error discards the pages already read.
func GLEIFGetDirectChildrenRecords(ctx context.Context, id string) ([]*LEIRecord, error) {
	var children []*LEIRecord

	last := 1
	link := gleifBaseURL + "/lei-records/" + id + "/direct-children"
	for i := 1; i <= last && link != ""; i++ {
		body, err := gleifGet(ctx, link)
		if err != nil {
			return nil, err
		}

		var result MultipleResponse
		if err := json.Unmarshal([]byte(body), &result); err != nil {
			return nil, err
		}

		for _, rec := range result.Data {
			children = append(children, &rec)
		}

		link = result.Links.Next
		last = result.Meta.Pagination.LastPage
	}

	return children, nil
}

// LocMatch checks if the LEI record matches the location of the organization entity.
func LocMatch(e *et.Event, orgent *dbt.Entity, rec *LEIRecord) bool {
	if rec == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	legal_addr := rec.Attributes.Entity.LegalAddress
	hq_addr := rec.Attributes.Entity.HeadquartersAddress
	if edges, err := e.Session.DB().OutgoingEdges(ctx, orgent,
		time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if loc, ok := a.Asset.(*contact.Location); ok {
					for _, p := range append([]LEIAddress{legal_addr, hq_addr}, rec.Attributes.Entity.OtherAddresses...) {
						if loc.PostalCode == p.PostalCode {
							return true
						}
					}
				}
			}
		}
	}

	var crs []*dbt.Entity
	if edges, err := e.Session.DB().IncomingEdges(ctx, orgent, time.Time{}, "organization"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*contact.ContactRecord); ok {
					crs = append(crs, a)
				}
			}
		}
	}

	for _, cr := range crs {
		if edges, err := e.Session.DB().OutgoingEdges(ctx, cr, time.Time{}, "location"); err == nil {
			for _, edge := range edges {
				if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
					if loc, ok := a.Asset.(*contact.Location); ok {
						for _, p := range append([]LEIAddress{legal_addr, hq_addr}, rec.Attributes.Entity.OtherAddresses...) {
							if loc.PostalCode == p.PostalCode {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}
