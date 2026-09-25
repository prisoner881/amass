// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/biter777/countries"
	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

var createOrgLock sync.Mutex

func CreateOrgAsset(sess et.Session, obj *dbt.Entity, rel oam.Relation, o *oamorg.Organization, src *et.Source) (*dbt.Entity, error) {
	if o == nil || o.Name == "" {
		return nil, errors.New("missing the organization name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	if o.Jurisdiction != "" {
		if code := countries.ByName(o.Jurisdiction); code.IsValid() {
			o.Jurisdiction = code.Alpha2()
		}
	}

	dName := o.Name
	orgent := lookupOrgByClaims(sess, dName, o, src)

	o.Name = genNormName(o)
	// Graph walk (may hit the shared DB). Do not hold createOrgLock.
	if orgent == nil && obj != nil {
		orgent = dedupChecks(sess, obj, o)
	}

	createOrgLock.Lock()
	defer createOrgLock.Unlock()

	if orgent == nil {
		orgent = lookupOrgByClaims(sess, dName, o, src)
	}
	if orgent == nil {
		if found, ok := nameExistsInSessionScope(sess, o); ok {
			orgent = found
		}
	}

	if orgent == nil {
		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		o.ID = genStableOrgID(o)
		var err error
		orgent, err = sess.DB().CreateAsset(ctx, o)
		if err != nil || orgent == nil {
			return nil, errors.New("failed to create the Organization asset")
		}
	}

	if orgent != nil {
		_, _ = CreateOrgNameClaim(sess, orgent, dName, src)

		if o.LegalName != "" {
			_, _ = CreateOrgLegalNameClaim(sess, orgent, o.LegalName, src)
		}
		if o.Jurisdiction != "" {
			_ = CreateOrgJurisdictionClaim(sess, orgent, o.Jurisdiction)
		}
		if o.RegistrationID != "" {
			_, _ = CreateOrgRegistrationIDClaim(sess, orgent, o.RegistrationID, src)
		}

		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		_, _ = sess.DB().CreateEntityProperty(ctx, orgent, &oamgen.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		if obj != nil && rel != nil && obj.ID != orgent.ID {
			ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
			defer cancel()

			if err := createRelation(ctx, sess, obj, rel, orgent, src); err != nil {
				return nil, err
			}
		}

		return orgent, nil
	}

	return nil, errors.New("failed to discover or create the Organization asset")
}

func lookupOrgByClaims(sess et.Session, name string, o *oamorg.Organization, src *et.Source) *dbt.Entity {
	if name == "" {
		name = o.Name
	}
	orgent, err := FindOrgByNameClaim(sess, name, src)
	if err != nil && o.LegalName != "" {
		orgent, _ = FindOrgByLegalNameClaim(sess, o.LegalName, src)
	}
	if o.Jurisdiction != "" {
		if o.RegistrationID != "" {
			orgent, _ = FindOrgByJurisdictionAndRegistrationIDClaim(sess, o.Jurisdiction, o.RegistrationID)
		}
		if orgent == nil {
			orgent, _ = FindOrgByNormNameAndJurisdictionClaim(sess, genNormName(o), o.Jurisdiction)
		}
	}
	return orgent
}

func genNormName(o *oamorg.Organization) string {
	name := o.Name

	if o.LegalName != "" {
		name = o.LegalName
	}

	return ExtractBrandName(strings.ToLower(name))
}

func genStableOrgID(o *oamorg.Organization) string {
	id := uuid.New().String()
	return fmt.Sprintf("%s:%s", o.Name, id)
}

func createRelation(ctx context.Context, sess et.Session, obj *dbt.Entity, rel oam.Relation, subject *dbt.Entity, src *et.Source) error {
	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: obj,
		ToEntity:   subject,
	})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = sess.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return err
}