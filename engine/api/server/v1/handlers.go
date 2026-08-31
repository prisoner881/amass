// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/InfluxCommunity/influxdb3-go/v2/influxdb3"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const maxBulkItems = 5000

type HealthCheckResponse struct {
	Result string `json:"result"`
}

type CreateSessionResponse struct {
	SessionToken string `json:"sessionToken"`
}

type ListSessionsResponse struct {
	SessionTokens []string `json:"sessionTokens"`
}

type SessionStatsResponse struct {
	WorkItemsCompleted int `json:"workItemsCompleted"`
	WorkItemsTotal     int `json:"workItemsTotal"`
}

type ScopeResponse struct {
	Data []json.RawMessage `json:"data"`
}

type AddAssetResponse struct {
	EntityID string `json:"entityID"`
}

// Bulk typed add: {"items":[ <OAM obj>, <OAM obj>, ... ]}
// where each item is arbitrary JSON object without "type".
type BulkAddAssetsRequest struct {
	Items []json.RawMessage `json:"items"`
}

type BulkAddAssetsResponse struct {
	Ingested int64 `json:"ingested"`
	Stored   int64 `json:"stored"`
	Failed   int64 `json:"failed"`
}

var (
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
)

type V1Handlers struct {
	ctx context.Context
	log *slog.Logger
	dis et.Dispatcher
	mgr et.SessionManager
}

func NewV1Handlers(ctx context.Context, dis et.Dispatcher, mgr et.SessionManager, log *slog.Logger) (*V1Handlers, error) {
	return &V1Handlers{
		ctx: ctx,
		log: log,
		dis: dis,
		mgr: mgr,
	}, nil
}

// HealthCheck godoc
//
// @Summary      Health check
// @Description  Returns a simple health indicator that the Amass Engine API is running.
// @Tags         system
// @Produce      json
// @Success      200  {object}  HealthCheckResponse
// @Router       /health [get]
func (v *V1Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	resp := HealthCheckResponse{Result: "Amass Engine OK"}

	writeJSON(w, http.StatusOK, resp)
}

// CreateSessionHandler godoc
//
// @Summary      Create a new engine session
// @Description  Creates a new Amass engine session using the provided configuration JSON.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        config  body      config.Config  true  "Engine configuration"
// @Success      201     {object}  CreateSessionResponse
// @Failure      400     {object}  ErrorResponse  "Invalid JSON or invalid configuration"
// @Failure      500     {object}  ErrorResponse  "Failed to create session"
// @Router       /sessions [post]
func (v *V1Handlers) CreateSessionHandler(w http.ResponseWriter, r *http.Request) {
	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	var config config.Config
	if err := json.Unmarshal(raw, &config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid configuration", err)
		return
	}
	// Populate FROM/TO in transformations
	for k, t := range config.Transformations {
		_ = t.Split(k)
	}

	sess, err := v.mgr.NewSession(&config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session", err)
		return
	}

	writeJSON(w, http.StatusCreated, CreateSessionResponse{
		SessionToken: sess.ID().String(),
	})
}

// ListSessionsHandler godoc
//
// @Summary      List active sessions
// @Description  Returns the session tokens for all currently active sessions.
// @Tags         sessions
// @Produce      json
// @Success      200  {object}  ListSessionsResponse
// @Failure      404  {object}  ErrorResponse  "Zero sessions found"
// @Router       /sessions/list [get]
func (v *V1Handlers) ListSessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessions := v.mgr.GetSessions()
	if len(sessions) == 0 {
		writeError(w, http.StatusNotFound, "zero sessions found", ErrNotFound)
		return
	}

	var resp ListSessionsResponse
	for _, sess := range sessions {
		resp.SessionTokens = append(resp.SessionTokens, sess.ID().String())
	}

	writeJSON(w, http.StatusOK, resp)
}

// TerminateSessionHandler godoc
//
// @Summary      Terminate a session
// @Description  Cancels an active session. Returns no content on success.
// @Tags         sessions
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      204
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token} [delete]
func (v *V1Handlers) TerminateSessionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	go v.mgr.CancelSession(token)
	w.WriteHeader(http.StatusNoContent)
}

// GetStatsHandler godoc
//
// @Summary      Get session statistics
// @Description  Returns the current runtime statistics for a session.
// @Tags         sessions
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      200  {object}  SessionStatsResponse
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token}/stats [get]
func (v *V1Handlers) GetStatsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}
	stats := sess.Stats()

	stats.RLock()
	writeJSON(w, http.StatusOK, stats)
	stats.RUnlock()
}

// GetScopeHandler godoc
//
// @Summary      Get session scope for an asset type
// @Description  Returns the scoped assets for the given session and asset type as an array of raw OAM JSON objects.
// @Tags         scope
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Param        asset_type     path  string  true  "Asset type (e.g., autonomoussystem, fqdn, ipaddress, netblock, location, organization)"
// @Success      200  {object}  ScopeResponse  "Response contains a 'data' array of raw OAM JSON"
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found or scope not found for asset type"
// @Router       /sessions/{session_token}/scope/{asset_type} [get]
func (v *V1Handlers) GetScopeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	var assets []oam.Asset
	switch assetType {
	case strings.ToLower(string(oam.AutonomousSystem)):
		for _, a := range sess.Scope().AutonomousSystems() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.FQDN)):
		for _, a := range sess.Scope().FQDNs() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.IPAddress)):
		for _, a := range sess.Scope().IPAddresses() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Netblock)):
		for _, a := range sess.Scope().Netblocks() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Location)):
		for _, a := range sess.Scope().Locations() {
			assets = append(assets, a)
		}
	case strings.ToLower(string(oam.Organization)):
		for _, a := range sess.Scope().Organizations() {
			assets = append(assets, a)
		}
	}

	if len(assets) == 0 {
		writeError(w, http.StatusNotFound,
			"session scope not found for the selected asset type", ErrNotFound)
		return
	}

	jsonArray := make([]json.RawMessage, len(assets))
	for i, a := range assets {
		if raw, err := a.JSON(); err == nil {
			jsonArray[i] = json.RawMessage(raw)
		}
	}

	response := struct {
		Data []json.RawMessage `json:"data"`
	}{
		Data: jsonArray,
	}
	writeJSON(w, http.StatusOK, response)
}

// AddAssetTypedHandler godoc
//
// @Summary      Add a single asset (typed by path)
// @Description  Submits a single OAM asset to the session. The asset type is provided in the URL path; the request body is a raw OAM JSON object without a 'type' field.
// @Tags         assets
// @Accept       json
// @Produce      json
// @Param        session_token  path  string          true  "Session token (UUID)"
// @Param        asset_type     path  string          true  "Asset type (e.g., autonomous_system, fqdn, ipaddress, netblock, location, organization)"
// @Param        asset          body  json.RawMessage true  "Raw OAM JSON object (without 'type')"
// @Success      200            {object}  AddAssetResponse
// @Failure      400            {object}  ErrorResponse  "Invalid session token, invalid JSON, or invalid asset object"
// @Failure      404            {object}  ErrorResponse  "Session not found"
// @Failure      500            {object}  ErrorResponse  "Failed to submit the asset"
// @Router       /sessions/{session_token}/assets/{asset_type} [post]
func (v *V1Handlers) AddAssetTypedHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	raw, err := readRawJSON(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	// minimal validation: ensure it’s valid JSON object
	if !looksLikeJSONObject(raw) {
		writeError(w, http.StatusBadRequest, "invalid JSON object", nil)
		return
	}

	asset, err := parseAsset(assetType, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid asset object", err)
		return
	}

	eid, err := v.PutAsset(v.ctx, sess, asset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit the asset", err)
		return
	}

	writeJSON(w, http.StatusOK, AddAssetResponse{
		EntityID: eid,
	})
}

// AddAssetsBulkHandler godoc
//
// @Summary      Add assets in bulk (typed by path)
// @Description  Submits multiple OAM assets to the session in one request. The asset type is provided in the URL path. Each item in 'items' is a raw OAM JSON object without a 'type' field.
// @Tags         assets
// @Accept       json
// @Produce      json
// @Param        session_token  path  string               true  "Session token (UUID)"
// @Param        asset_type     path  string               true  "Asset type (e.g., autonomous_system, fqdn, ipaddress, netblock, location, organization)"
// @Param        request        body  BulkAddAssetsRequest true  "Bulk add request payload"
// @Success      200            {object}  BulkAddAssetsResponse
// @Failure      400            {object}  ErrorResponse  "Invalid session token, invalid JSON, empty items, or no valid items"
// @Failure      404            {object}  ErrorResponse  "Session not found"
// @Failure      413            {object}  ErrorResponse  "Too many items in bulk request"
// @Failure      500            {object}  BulkAddAssetsResponse  "Server failure (response includes ingested/stored/failed)"
// @Router       /sessions/{session_token}/assets/{asset_type}:bulk [post]
func (v *V1Handlers) AddAssetsBulkHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]
	assetType := strings.ToLower(strings.TrimSpace(vars["asset_type"]))

	// Check if the session token is valid
	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}
	// Check if the session exists
	// and if the session is not already terminated
	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	var req BulkAddAssetsRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "items must be non-empty", nil)
		return
	}
	if len(req.Items) > maxBulkItems {
		writeError(w, http.StatusRequestEntityTooLarge,
			"too many items in bulk request", errors.New("max items exceeded"))
		return
	}

	assets := make([]oam.Asset, 0, len(req.Items))
	for _, raw := range req.Items {
		if a, err := parseAsset(assetType, raw); err == nil {
			assets = append(assets, a)
		}
	}

	ingested := int64(len(assets))
	if ingested == 0 {
		writeError(w, http.StatusBadRequest, "no valid JSON objects in items", nil)
		return
	}

	stored, err := v.PutAssets(v.ctx, sess, assets)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BulkAddAssetsResponse{
			Ingested: ingested,
			Stored:   0,
			Failed:   ingested,
		})
		return
	}

	failed := ingested - stored
	writeJSON(w, http.StatusOK, BulkAddAssetsResponse{
		Ingested: ingested,
		Stored:   stored,
		Failed:   failed,
	})
}

// --- Additions for the backlog and handler-latency dashboard endpoints ---
//
// These two endpoints are deliberately separate in shape, because the data
// behind them lives in two genuinely different places:
//
// GetBacklogHandler reads Session.Backlog().Counts(atype) directly - data
// that already exists in memory for every running session, no new tracking
// added anywhere. It is correctly scoped under /sessions/{session_token},
// matching every other per-session endpoint in this file.
//
// GetHandlerStatsHandler queries InfluxDB, using the existing (write-only
// until now) telemetry in engine/registry/pipelines.go's handlerTask func.
// That telemetry tags each data point only with "handler" (an
// AssetType-Position string) - there is no session identifier anywhere on
// the write side. So this endpoint is NOT session-scoped, on purpose: it
// reflects what the underlying data actually is (engine-process-wide),
// rather than presenting per-session numbers that don't exist. If multiple
// sessions run concurrently against the same engine, this data is
// commingled across all of them - worth knowing before relying on it,
// not something this endpoint can fix without also changing the write
// side to add a session tag.

// BacklogBucket represents one asset type's current backlog state.
// Queue is the pipeline's own internal queue depth for this asset
// type (distinct from Waiting, the backlog's own pre-claim count) -
// added specifically to distinguish two different bottleneck shapes:
// Waiting high with Queue near its MaxQueued ceiling (see
// engine/dispatcher/dispatcher.go's own limitsByAssetType) means
// handlers can't drain work fast enough; Waiting high with Queue near
// zero means the dispatcher's own claim rate (PerSessBurst) is itself
// the constraint, since the pipeline is starved rather than backed
// up. Neither of the existing three columns alone could distinguish
// these two, meaningfully different situations from each other.
type BacklogBucket struct {
	AssetType string `json:"asset_type"`
	Waiting   int64  `json:"waiting"`
	Leased    int64  `json:"leased"`
	Queue     int    `json:"queue"`
	Processed int64  `json:"processed"`
}

// BacklogResponse is the payload for GetBacklogHandler.
//
// ActiveConnections/MaxConnections reflect Session.NetSem()'s current
// utilization - a single, engine-wide value (not per-bucket, unlike
// everything above) since it's a resource shared across every plugin
// and asset type simultaneously, not scoped to any one of them; a
// bucket could show a perfectly healthy Queue/Waiting picture while
// this shared pool is still the actual, invisible-to-any-single-
// bucket bottleneck.
//
// PrefilterScanned/PrefilterOpen are the port_prefilter feature's own
// cumulative counters (see support.PrefilterStats) - intended for
// development-time visibility into how effective the pre-filter
// actually is at a given target, not for any production
// decision-making. These are plain, session-independent globals; see
// support.PrefilterStats's own doc comment for why that's a
// deliberate, correct choice for this fork's specific deployment
// model (one session per engine process, containers brought down
// between separate enumerations) rather than a general-purpose
// design.
type BacklogResponse struct {
	Buckets           []BacklogBucket `json:"buckets"`
	ActiveConnections int             `json:"active_connections"`
	MaxConnections    int             `json:"max_connections"`
	PrefilterScanned  int64           `json:"prefilter_scanned"`
	PrefilterOpen     int64           `json:"prefilter_open"`
}

// allTrackedAssetTypes lists every asset type the backlog is queried for.
// This is the full set defined in open-asset-model, not a curated subset -
// buckets with zero activity (Queued+Leased+Processed == 0) are omitted
// from the response rather than hardcoding which types matter, since that
// set can change as new plugins are added.
var allTrackedAssetTypes = []oam.AssetType{
	oam.Account, oam.AutnumRecord, oam.AutonomousSystem, oam.ContactRecord,
	oam.DomainRecord, oam.File, oam.FQDN, oam.FundsTransfer, oam.Identifier,
	oam.IPAddress, oam.IPNetRecord, oam.Location, oam.Netblock,
	oam.Organization, oam.Person, oam.Phone, oam.Product, oam.ProductRelease,
	oam.Service, oam.TLSCertificate, oam.URL,
}

// GetBacklogHandler godoc
//
// @Summary      Get per-asset-type backlog counts for a session
// @Description  Returns, for each asset type with any activity, the number of entities waiting, currently leased (in flight), sitting in the pipeline's own internal queue, and already processed - plus session-wide connection semaphore utilization and cumulative port_prefilter statistics. Development/testing tooling: PrefilterScanned/PrefilterOpen use plain, session-independent counters (see support.PrefilterStats), correct for this fork's one-session-per-process deployment model but not intended for use in a multi-session or long-lived-process deployment.
// @Tags         sessions
// @Produce      json
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      200  {object}  BacklogResponse
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Router       /sessions/{session_token}/backlog [get]
func (v *V1Handlers) GetBacklogHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sid := vars["session_token"]

	token, err := uuid.Parse(sid)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session token", err)
		return
	}

	sess := v.mgr.GetSession(token)
	if sess == nil {
		writeError(w, http.StatusNotFound, "session not found", ErrNotFound)
		return
	}

	pipelines := sess.Pipelines()

	var buckets []BacklogBucket
	for _, atype := range allTrackedAssetTypes {
		waiting, leased, done, err := sess.Backlog().Counts(atype)
		if err != nil {
			continue
		}

		var queueLen int
		if p, ok := pipelines[atype]; ok && p != nil && p.Queue != nil {
			queueLen = p.Queue.Len()
		}

		if waiting == 0 && leased == 0 && done == 0 && queueLen == 0 {
			continue
		}
		buckets = append(buckets, BacklogBucket{
			AssetType: string(atype),
			Waiting:   waiting,
			Leased:    leased,
			Queue:     queueLen,
			Processed: done,
		})
	}

	scanned, open := support.PrefilterStats()

	writeJSON(w, http.StatusOK, BacklogResponse{
		Buckets:           buckets,
		ActiveConnections: sess.NetSem().InUse(),
		MaxConnections:    sess.NetSem().Cap(),
		PrefilterScanned:  scanned,
		PrefilterOpen:     open,
	})
}

// HandlerStat represents one handler's average execution time and call
// count over the query window.
type HandlerStat struct {
	Handler       string  `json:"handler"`
	AvgDurationNS float64 `json:"avg_duration_ns"`
	CallCount     int64   `json:"call_count"`
}

// HandlerStatsResponse is the payload for GetHandlerStatsHandler.
type HandlerStatsResponse struct {
	WindowMinutes int           `json:"window_minutes"`
	Handlers      []HandlerStat `json:"handlers"`
}

// GetHandlerStatsHandler godoc
//
// @Summary      Get per-handler average execution time
// @Description  Queries InfluxDB for the handler_duration measurement written by the engine's pipeline task wrapper, returning average duration and call count per handler over the last 15 minutes, sorted slowest first. Not session-scoped - see the note above GetBacklogHandler for why. Returns 503 if INFLUX_* environment variables are not configured.
// @Tags         telemetry
// @Produce      json
// @Success      200  {object}  HandlerStatsResponse
// @Failure      503  {object}  ErrorResponse  "InfluxDB not configured or unreachable"
// @Router       /handler-stats [get]
func (v *V1Handlers) GetHandlerStatsHandler(w http.ResponseWriter, r *http.Request) {
	client, err := influxdb3.NewFromEnv()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "influxdb not configured", err)
		return
	}
	defer func() { _ = client.Close() }()

	const windowMinutes = 15
	query := `SELECT handler, AVG(duration) AS avg_duration_ns, COUNT(*) AS call_count
FROM handler_duration
WHERE time >= now() - INTERVAL '15 minutes'
GROUP BY handler
ORDER BY avg_duration_ns DESC`

	iter, err := client.Query(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "influxdb query failed", err)
		return
	}

	var stats []HandlerStat
	for iter.Next() {
		row := iter.Value()

		handler, _ := row["handler"].(string)
		if handler == "" {
			continue
		}

		var avg float64
		switch val := row["avg_duration_ns"].(type) {
		case float64:
			avg = val
		case int64:
			avg = float64(val)
		}

		var count int64
		switch val := row["call_count"].(type) {
		case int64:
			count = val
		case float64:
			count = int64(val)
		}

		stats = append(stats, HandlerStat{
			Handler:       handler,
			AvgDurationNS: avg,
			CallCount:     count,
		})
	}
	if err := iter.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error reading query results", err)
		return
	}

	writeJSON(w, http.StatusOK, HandlerStatsResponse{
		WindowMinutes: windowMinutes,
		Handlers:      stats,
	})
}
