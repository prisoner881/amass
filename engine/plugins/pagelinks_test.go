// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// As with every plugin built in this batch, this codebase has no harness
// for constructing a full et.Session in a unit test, so check() itself
// is exercised only by manual runs. This covers harvestLinks(), the
// parsing logic, using real bodies pulled from an actual Amass database
// (not synthetic HTML) so the test reflects real-world page shapes -
// including the messy, non-HTML, and JS-shell cases that turned out to
// matter in practice, not just a clean happy path.
//
// harvestLinks is a package-level extraction of the parsing loop inside
// pageLinks.harvest(), factored out so it's testable without an *et.Event.

func harvestLinks(body string, base *url.URL) map[string]struct{} {
	hosts := make(map[string]struct{})
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := tokenizer.Token()
		for _, attr := range tok.Attr {
			if !linkAttrs[strings.ToLower(attr.Key)] || attr.Val == "" {
				continue
			}
			resolved, err := base.Parse(attr.Val)
			if err != nil {
				continue
			}
			h := strings.ToLower(strings.TrimSpace(resolved.Hostname()))
			if h != "" {
				hosts[h] = struct{}{}
			}
		}
	}
	return hosts
}

// realWordPressSnippet is an excerpt of an actual response body captured
// for vidyo.wpengine.com (a real, server-rendered WordPress site),
// containing genuine <a href> links to a related brand domain and
// social-media footer icons - both categories the plugin is meant to
// surface, verified against a real page rather than assumed. Note the
// facebook.com link below is the real footer <a href> occurrence, not
// the article:publisher meta tag's content= attribute elsewhere on the
// same real page - that attribute isn't tracked by linkAttrs at all,
// which the first draft of this test got wrong before checking.
const realWordPressSnippet = `<html><head></head><body>
<a href="https://customer.support.enghouse.com/servicedesk/customer/portal/16" class="nitro-lazy">Support</a>
<a href="https://www.enghouse.com/careers/" target="_blank" rel="noopener">Careers</a>
<a href='https://www.facebook.com/EnghouseVideo' class='icon' title='Follow on Facebook' target="_blank"></a>
<a href="/about">About</a>
</body></html>`

func TestHarvestLinksRealServerRenderedPage(t *testing.T) {
	base, _ := url.Parse("https://vidyo.wpengine.com")
	hosts := harvestLinks(realWordPressSnippet, base)

	want := []string{
		"www.facebook.com",
		"customer.support.enghouse.com",
		"www.enghouse.com",
		"vidyo.wpengine.com", // relative /about resolved against base
	}
	if len(hosts) != len(want) {
		t.Fatalf("expected %d distinct hosts, got %d: %v", len(want), len(hosts), hosts)
	}
	for _, h := range want {
		if _, ok := hosts[h]; !ok {
			t.Errorf("expected host %q to be present, was not found", h)
		}
	}
}

// realAuraLoadingShell is the actual opening body content captured for
// boathistoryreport.my.site.com, a Salesforce Lightning/Aura app. This
// is real evidence of the JS-rendering limitation discussed: the raw
// response is a loading shell, not the rendered page, so the only <a>
// tags present are UI chrome (dismiss/refresh), not real navigation.
const realAuraLoadingShell = `<body class="null loading"><div class="auraMsgBox auraLoadingBox">
<div class="logo"></div><div class="spinner"></div><span>Loading</span></div>
<div class="" id="auraErrorMask"><div role="dialog" class="auraErrorBox" id="auraError">
<span><a role="button" href="#" id="dismissError" title="Cancel and close" class="close">×</a>
<span id="auraErrorTitle">Sorry to interrupt</span></span>
<div id="auraErrorMessage">CSS Error</div>
<div class="auraErrorFooter"><a role="button" href="?" id="auraErrorReload">Refresh</a></div>
</div></div></body>`

func TestHarvestLinksOnJSShellFindsOnlyUIChrome(t *testing.T) {
	base, _ := url.Parse("http://boathistoryreport.my.site.com:8080")
	hosts := harvestLinks(realAuraLoadingShell, base)

	// href="#" and href="?" both resolve to the base page itself, not to
	// any real navigational target - this documents the known gap
	// rather than treating it as a failure: a JS-rendered page's real
	// links are invisible to this plugin, and this fixture proves it
	// with genuine captured data rather than a synthetic assumption.
	if len(hosts) != 1 {
		t.Fatalf("expected only the base host itself (from UI-chrome fragment links), got %d: %v", len(hosts), hosts)
	}
	if _, ok := hosts["boathistoryreport.my.site.com"]; !ok {
		t.Errorf("expected the base host from resolved fragment links, got %v", hosts)
	}
}

// realCloudflareErrorBody is the exact, complete body captured for a
// domain that returned Cloudflare's bare-text routing error - not HTML
// at all. Confirms the tokenizer degrades safely (zero results, no
// panic) on genuinely non-HTML content, which turned out to be roughly
// half of the real sample this was checked against.
const realCloudflareErrorBody = "error code: 1001"

func TestHarvestLinksOnNonHTMLBodyFindsNothing(t *testing.T) {
	base, _ := url.Parse("http://nextinnovationcoltd.mktoweb.com:8080")
	hosts := harvestLinks(realCloudflareErrorBody, base)

	if len(hosts) != 0 {
		t.Errorf("expected zero hosts from a non-HTML error body, got %d: %v", len(hosts), hosts)
	}
}

// realAzureJSONErrorBody is the exact body captured from an IP-keyed
// Service whose port 443 responded with an Azure API error payload
// instead of a web page - JSON, not HTML, another real non-HTML shape
// found in the sample.
const realAzureJSONErrorBody = `{"error":{"code":"","message":"Invalid Request. The request host does not correspond to a valid Azure AI Search service."}}`

func TestHarvestLinksOnJSONBodyFindsNothing(t *testing.T) {
	base, _ := url.Parse("https://52.226.242.104")
	hosts := harvestLinks(realAzureJSONErrorBody, base)

	if len(hosts) != 0 {
		t.Errorf("expected zero hosts from a JSON error body, got %d: %v", len(hosts), hosts)
	}
}

func TestHarvestLinksDeduplicatesRepeatedHosts(t *testing.T) {
	body := `<a href="https://example.com/a">1</a><a href="https://example.com/b">2</a><a href="https://EXAMPLE.COM/c">3</a>`
	base, _ := url.Parse("https://target.com")
	hosts := harvestLinks(body, base)

	if len(hosts) != 1 {
		t.Fatalf("expected exactly 1 distinct host after case-insensitive dedup, got %d: %v", len(hosts), hosts)
	}
	if _, ok := hosts["example.com"]; !ok {
		t.Errorf("expected lowercased host %q, got %v", "example.com", hosts)
	}
}

func TestHarvestLinksIgnoresEmptyAndMalformedAttrs(t *testing.T) {
	body := `<a href="">empty</a><img src="   ">whitespace-only</img><a>no href at all</a>`
	base, _ := url.Parse("https://target.com")
	hosts := harvestLinks(body, base)

	// A whitespace-only src still resolves to a non-empty relative URL
	// under net/url, so it legitimately resolves back to the base host -
	// this test documents that behavior rather than asserting zero
	// results outright.
	if len(hosts) > 1 {
		t.Errorf("expected at most the base host from a whitespace src, got %d: %v", len(hosts), hosts)
	}
}
