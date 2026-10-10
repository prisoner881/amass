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
// ListDone ∩ open_port (prefilter TTL) ∩ ¬Protocol-Probes (plugin TTL) ∩
// resolved by an FQDN under a seed domain. Does not use fqdn_by_domains —
// that function is not in stock asset-db.
//
// It starts from the Done IPs, as the serial walk does, so every lookup is
// an index probe keyed by one IP: its tags (entity_id, ...), its incoming
// dns_record edges (to_entity_id), and the FQDN behind each edge. The cost
// grows with the number of Done IPs, not with the size of the database.
// (Starting from the seed domains instead needs a pattern match per seed,
// which the planner cannot run as an index range inside a join; it read the
// whole entity and fqdn tables and hit statement_timeout on large
// databases.) OFFSET 0 keeps each subquery a per-row probe: without it the
// planner can turn EXISTS into a hash semi-join over a full table scan.
const missListSQL = `
WITH seeds AS MATERIALIZED (
    SELECT DISTINCT reverse(lower(trim(s))) AS rd
    FROM unnest(string_to_array($2::text, E'\n')) AS s
    WHERE trim(s) <> ''
)
SELECT d.id::text
FROM unnest($1::bigint[]) AS d(id)
WHERE EXISTS (
    SELECT 1 FROM entity_tag t
    WHERE t.entity_id = d.id
      AND t.property_name = 'open_port'
      AND t.updated_at >= $3
    OFFSET 0
)
AND NOT EXISTS (
    SELECT 1 FROM entity_tag t
    WHERE t.entity_id = d.id
      AND t.property_name = 'last_monitored'
      AND t.property_value = 'Protocol-Probes'
      AND t.updated_at >= $4
    OFFSET 0
)
AND EXISTS (
    SELECT 1
    FROM edge ed
    JOIN entity e ON e.entity_id = ed.from_entity_id
    JOIN fqdn f ON f.id = e.row_id
    WHERE ed.to_entity_id = d.id
      AND ed.label = 'dns_record'
      AND e.etype_id = (SELECT id FROM entity_type_lu WHERE name = 'fqdn')
      AND EXISTS (
          SELECT 1 FROM seeds sd
          WHERE f.reverse_fqdn = sd.rd
             OR starts_with(f.reverse_fqdn, sd.rd || '.')
      )
    OFFSET 0
)
LIMIT $5
`

// missListChunk is how many Done IPs go into one miss-list statement. Each
// statement must finish inside asset-db's 60s statement_timeout even with a
// cold cache (about 1ms per IP in the worst case measured).
var missListChunk = 5000

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
	seeds := sweepSeedDomains(s)
	if len(seeds) == 0 {
		return nil, true, nil
	}

	ints := make([]int64, 0, len(doneIDs))
	seen := make(map[int64]struct{}, len(doneIDs))
	for _, id := range doneIDs {
		n, perr := strconv.ParseInt(id, 10, 64)
		if perr != nil {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		ints = append(ints, n)
	}
	if len(ints) == 0 {
		return nil, true, nil
	}

	seedList := strings.Join(seeds, "\n")
	var out []string
	for start := 0; start < len(ints) && len(out) < sweepMaxResubmit; start += missListChunk {
		if s.Done() {
			break
		}
		end := min(start+missListChunk, len(ints))
		chunk, qerr := missListQuery(s.Ctx(), db, ints[start:end], seedList,
			prefilterSince, protoSince, sweepMaxResubmit-len(out))
		if qerr != nil {
			return nil, false, qerr
		}
		out = append(out, chunk...)
	}
	return out, true, nil
}

// missListQuery runs missListSQL over one chunk of Done IPs.
func missListQuery(ctx context.Context, db *sql.DB, ids []int64, seeds string, prefilterSince, protoSince time.Time, limit int) ([]string, error) {
	// 90s is past asset-db's 60s statement_timeout on this *sql.DB so
	// a stuck SELECT surfaces as a Postgres error, not a Go race.
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, missListSQL,
		pgInt8Array(ids),
		seeds,
		prefilterSince.UTC(),
		protoSince.UTC(),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("miss-list query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
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
