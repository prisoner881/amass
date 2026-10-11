// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

type dnsApex struct {
	name   string
	plugin *dnsPlugin
}

func (d *dnsApex) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if e.Meta == nil {
		return nil
	} else if m, ok := e.Meta.(*support.FQDNMeta); !ok || len(m.RecordTypes) == 0 {
		return nil
	}

	if apex := d.plugin.apexOf(fqdn.Name); apex != nil {
		d.store(e, fqdn.Name, e.Entity, apex)
	}
	return nil
}

// apexOf returns the closest known zone apex that is a parent of name, or
// nil when there is none or name is that apex itself.
func (d *dnsPlugin) apexOf(name string) *dbt.Entity {
	var apexName string
	best := len(name)
	for _, n := range d.getApexList() {
		if !strings.HasSuffix(name, "."+n) {
			continue
		}
		if idx := strings.Index(name, n); idx != -1 && idx != 0 && idx < best {
			best = idx
			apexName = n
		}
	}
	if apexName == "" {
		return nil
	}

	if apex := d.getApex(apexName); apex != nil && apex.Asset.Key() != name {
		return apex
	}
	return nil
}

func (d *dnsApex) store(e *et.Event, name string, fqdn, apex *dbt.Entity) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
	defer cancel()

	if _, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: apex,
		ToEntity:   fqdn,
	}); err == nil {
		e.Session.Log().Info("relationship discovered", "from", apex.Asset.Key(), "relation",
			"node", "to", name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
