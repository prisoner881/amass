// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package protocol_probes

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository/postgres"
)

// missListSQL is the batch equivalent of the serial walk's filters:
// ListDone ∩ seed dns_record ∩ open_port (prefilter TTL) ∩ ¬Protocol-Probes
// (plugin TTL). Does not use fqdn_by_domains — that function is not in
// stock asset-db. reverse_fqdn prefix match is the same predicate.
const missListSQL = `
WITH done AS (
    SELECT unnest($1::bigint[]) AS entity_id
),
seeds AS (
    SELECT lower(trim(s)) AS domain
    FROM unnest(string_to_array($2::text, E'\n')) AS s
    WHERE trim(s) <> ''
),
seed_fqdn AS (
    SELECT e.entity_id
    FROM seeds sd
    JOIN fqdn f
      ON f.reverse_fqdn = reverse(sd.domain)
      OR f.reverse_fqdn LIKE reverse(sd.domain) || '.%'
    JOIN entity e ON e.row_id = f.id
    JOIN entity_type_lu lu ON lu.id = e.etype_id AND lu.name = 'fqdn'
)
SELECT DISTINCT ed.to_entity_id::text
FROM seed_fqdn s
JOIN edge ed
  ON ed.from_entity_id = s.entity_id
 AND ed.label = 'dns_record'
JOIN done d ON d.entity_id = ed.to_entity_id
WHERE EXISTS (
    SELECT 1 FROM entity_tag t
    WHERE t.entity_id = ed.to_entity_id
      AND t.property_name = 'open_port'
      AND t.updated_at >= $3
)
AND NOT EXISTS (
    SELECT 1 FROM entity_tag t
    WHERE t.entity_id = ed.to_entity_id
      AND t.property_name = 'last_monitored'
      AND t.property_value = 'Protocol-Probes'
      AND t.updated_at >= $4
)
LIMIT $5
`

func postgresSQL(s et.Session) *sql.DB {
	if s == nil || s.DB() == nil {
		return nil
	}
	p, ok := s.DB().(*postgres.PostgresRepository)
	if !ok || p == nil {
		return nil
	}
	return p.DB
}

// missListBatch returns entity IDs that need Protocol-Probes requeue.
// batched=false means the caller should use the serial walk (not postgres,
// empty input, or no seed domains). A non-nil error means try the walk.
func missListBatch(s et.Session, doneIDs []string, prefilterSince, protoSince time.Time) (ids []string, batched bool, err error) {
	db := postgresSQL(s)
	if db == nil {
		return nil, false, nil
	}
	if len(doneIDs) == 0 {
		return nil, true, nil
	}
	var seeds []string
	if s.Config() != nil {
		seeds = s.Config().Domains()
	}
	if len(seeds) == 0 {
		return nil, true, nil
	}

	ints := make([]int64, 0, len(doneIDs))
	for _, id := range doneIDs {
		n, perr := strconv.ParseInt(id, 10, 64)
		if perr != nil {
			continue
		}
		ints = append(ints, n)
	}
	if len(ints) == 0 {
		return nil, true, nil
	}

	ctx, cancel := context.WithTimeout(s.Ctx(), 30*time.Second)
	defer cancel()

	rows, qerr := db.QueryContext(ctx, missListSQL,
		pgInt8Array(ints),
		strings.Join(seeds, "\n"),
		prefilterSince.UTC(),
		protoSince.UTC(),
		sweepMaxResubmit,
	)
	if qerr != nil {
		return nil, false, fmt.Errorf("miss-list query: %w", qerr)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var id string
		if serr := rows.Scan(&id); serr != nil {
			return nil, false, serr
		}
		out = append(out, id)
	}
	return out, true, rows.Err()
}

func pgInt8Array(ids []int64) string {
	var b strings.Builder
	b.Grow(2 + len(ids)*12)
	b.WriteByte('{')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatInt(id, 10))
	}
	b.WriteByte('}')
	return b.String()
}
