package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auditvision/internal/model"
)

const tsFormat = time.RFC3339Nano

type PgStore struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*PgStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}

	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = 60 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	s := &PgStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

func (s *PgStore) Close() { s.pool.Close() }

// ─────────────────────────────────────────────────────────────────────────────
// Migrations — idempotent, runs on every startup
// ─────────────────────────────────────────────────────────────────────────────

func (s *PgStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		-- Main events table
		CREATE TABLE IF NOT EXISTS audit_events (
		    id             BIGSERIAL,
		    audit_id       TEXT        NOT NULL,
		    ts             TIMESTAMPTZ NOT NULL,
		    actor          TEXT        NOT NULL DEFAULT '',
		    actor_type     TEXT        NOT NULL DEFAULT '',
		    source         TEXT        NOT NULL DEFAULT '',
		    source_ip      TEXT        NOT NULL DEFAULT '',
		    user_agent     TEXT        NOT NULL DEFAULT '',
		    verb           TEXT        NOT NULL DEFAULT '',
		    resource       TEXT        NOT NULL DEFAULT '',
		    subresource    TEXT        NOT NULL DEFAULT '',
		    api_group      TEXT        NOT NULL DEFAULT '',
		    api_version    TEXT        NOT NULL DEFAULT '',
		    namespace      TEXT        NOT NULL DEFAULT '',
		    name           TEXT        NOT NULL DEFAULT '',
		    result         INT         NOT NULL DEFAULT 0,
		    decision       TEXT        NOT NULL DEFAULT '',
		    reason         TEXT        NOT NULL DEFAULT '',
		    stage          TEXT        NOT NULL DEFAULT '',
		    level          TEXT        NOT NULL DEFAULT '',
		    request_uri    TEXT        NOT NULL DEFAULT '',
		    action_summary TEXT        NOT NULL DEFAULT '',
		    changes        JSONB       NOT NULL DEFAULT '[]',
		    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    PRIMARY KEY (id),
		    UNIQUE (audit_id)
		);

		CREATE INDEX IF NOT EXISTS idx_ae_ts        ON audit_events (ts DESC);
		CREATE INDEX IF NOT EXISTS idx_ae_namespace ON audit_events (namespace);
		CREATE INDEX IF NOT EXISTS idx_ae_actor     ON audit_events (actor);
		CREATE INDEX IF NOT EXISTS idx_ae_verb      ON audit_events (verb);
		CREATE INDEX IF NOT EXISTS idx_ae_resource  ON audit_events (resource);
		CREATE INDEX IF NOT EXISTS idx_ae_ns_name   ON audit_events (namespace, name);

		-- Deployment snapshots for enrichment
		CREATE TABLE IF NOT EXISTS deployment_snapshots (
		    namespace   TEXT        NOT NULL,
		    name        TEXT        NOT NULL,
		    replicas    INT         NOT NULL DEFAULT 1,
		    containers  JSONB       NOT NULL DEFAULT '{}',
		    env         JSONB       NOT NULL DEFAULT '{}',
		    resources   JSONB       NOT NULL DEFAULT '{}',
		    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    PRIMARY KEY (namespace, name)
		);
		ALTER TABLE deployment_snapshots ADD COLUMN IF NOT EXISTS env       JSONB NOT NULL DEFAULT '{}';
		ALTER TABLE deployment_snapshots ADD COLUMN IF NOT EXISTS resources JSONB NOT NULL DEFAULT '{}';

		-- ConfigMap/Secret snapshots for key-level diff
		CREATE TABLE IF NOT EXISTS configmap_snapshots (
		    namespace   TEXT        NOT NULL,
		    name        TEXT        NOT NULL,
		    data        JSONB       NOT NULL DEFAULT '{}',
		    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    PRIMARY KEY (namespace, name)
		);

		-- Exclusion rules — collector drops matching events before storing
		CREATE TABLE IF NOT EXISTS exclusion_rules (
		    id          BIGSERIAL    PRIMARY KEY,
		    name        TEXT         NOT NULL DEFAULT '',
		    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
		    namespace   TEXT         NOT NULL DEFAULT '',
		    actor       TEXT         NOT NULL DEFAULT '',
		    actor_type  TEXT         NOT NULL DEFAULT '',
		    verb        TEXT         NOT NULL DEFAULT '',
		    resource    TEXT         NOT NULL DEFAULT '',
		    comment     TEXT         NOT NULL DEFAULT '',
		    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return err
	}
	log.Println("store: migrations ok")
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// EventStore implementation
// ─────────────────────────────────────────────────────────────────────────────

func (s *PgStore) InsertEvent(ctx context.Context, ev model.NormalizedEvent) error {
	changesJSON, err := json.Marshal(ev.Changes)
	if err != nil {
		return fmt.Errorf("marshal changes: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_events (
		    audit_id, ts, actor, actor_type, source, source_ip, user_agent,
		    verb, resource, subresource, api_group, api_version,
		    namespace, name, result, decision, reason,
		    stage, level, request_uri, action_summary, changes
		) VALUES (
		    $1,$2,$3,$4,$5,$6,$7,
		    $8,$9,$10,$11,$12,
		    $13,$14,$15,$16,$17,
		    $18,$19,$20,$21,$22
		)
		ON CONFLICT (audit_id) DO NOTHING`,
		ev.AuditID, ev.Timestamp, ev.Actor, ev.ActorType, ev.Source, ev.SourceIP, ev.UserAgent,
		ev.Verb, ev.Resource, ev.Subresource, ev.APIGroup, ev.APIVersion,
		ev.Namespace, ev.Name, ev.Result, ev.Decision, ev.Reason,
		ev.Stage, ev.Level, ev.RequestURI, ev.ActionSummary, changesJSON,
	)
	return err
}

func (s *PgStore) GetEvents(ctx context.Context, f model.EventFilter) ([]model.NormalizedEvent, error) {
	where, args := buildWhere(f)
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT audit_id, ts, actor, actor_type, source, source_ip, user_agent,
		       verb, resource, subresource, api_group, api_version,
		       namespace, name, result, decision, reason,
		       stage, level, request_uri, action_summary, changes,
		       COALESCE(risk_score, ''), COALESCE(risk_reason, '')
		FROM audit_events
		%s
		ORDER BY ts DESC
		LIMIT %d OFFSET %d
	`, where, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []model.NormalizedEvent
	for rows.Next() {
		var ev model.NormalizedEvent
		var ts time.Time
		var changesJSON []byte
		err := rows.Scan(
			&ev.AuditID, &ts, &ev.Actor, &ev.ActorType, &ev.Source, &ev.SourceIP, &ev.UserAgent,
			&ev.Verb, &ev.Resource, &ev.Subresource, &ev.APIGroup, &ev.APIVersion,
			&ev.Namespace, &ev.Name, &ev.Result, &ev.Decision, &ev.Reason,
			&ev.Stage, &ev.Level, &ev.RequestURI, &ev.ActionSummary, &changesJSON,
			&ev.RiskScore, &ev.RiskReason,
		)
		if err != nil {
			return nil, err
		}
		ev.Timestamp = ts.UTC().Format(tsFormat)
		if err := json.Unmarshal(changesJSON, &ev.Changes); err != nil {
			ev.Changes = nil
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (s *PgStore) GetEventByID(ctx context.Context, auditID string) (*model.NormalizedEvent, error) {
	var ev model.NormalizedEvent
	var ts time.Time
	var changesJSON []byte

	err := s.pool.QueryRow(ctx, `
		SELECT audit_id, ts, actor, actor_type, source, source_ip, user_agent,
		       verb, resource, subresource, api_group, api_version,
		       namespace, name, result, decision, reason,
		       stage, level, request_uri, action_summary, changes,
		       COALESCE(risk_score, ''), COALESCE(risk_reason, '')
		FROM audit_events WHERE audit_id = $1`, auditID).Scan(
		&ev.AuditID, &ts, &ev.Actor, &ev.ActorType, &ev.Source, &ev.SourceIP, &ev.UserAgent,
		&ev.Verb, &ev.Resource, &ev.Subresource, &ev.APIGroup, &ev.APIVersion,
		&ev.Namespace, &ev.Name, &ev.Result, &ev.Decision, &ev.Reason,
		&ev.Stage, &ev.Level, &ev.RequestURI, &ev.ActionSummary, &changesJSON,
		&ev.RiskScore, &ev.RiskReason,
	)
	if err != nil {
		return nil, err
	}
	ev.Timestamp = ts.UTC().Format(tsFormat)
	if err := json.Unmarshal(changesJSON, &ev.Changes); err != nil {
		ev.Changes = nil
	}
	return &ev, nil
}

func (s *PgStore) CountEvents(ctx context.Context, f model.EventFilter) (int, error) {
	where, args := buildWhere(f)
	query := fmt.Sprintf("SELECT COUNT(*) FROM audit_events %s", where)
	var count int
	err := s.pool.QueryRow(ctx, query, args...).Scan(&count)
	return count, err
}

func (s *PgStore) GetSummary(ctx context.Context, f model.EventFilter) (*model.SummaryResponse, error) {
	where, args := buildWhere(f)

	var total, human, sa, system, mutations, errors int
	err := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE actor_type = 'human'),
		    COUNT(*) FILTER (WHERE actor_type = 'serviceaccount'),
		    COUNT(*) FILTER (WHERE actor_type = 'system'),
		    COUNT(*) FILTER (WHERE verb IN ('create','update','patch','delete')),
		    COUNT(*) FILTER (WHERE result >= 400)
		FROM audit_events %s`, where), args...).
		Scan(&total, &human, &sa, &system, &mutations, &errors)
	if err != nil {
		return nil, err
	}

	resp := &model.SummaryResponse{
		TotalEvents:          total,
		HumanEvents:          human,
		ServiceAccountEvents: sa,
		SystemEvents:         system,
		MutationEvents:       mutations,
		ErrorEvents:          errors,
		TopActors:            map[string]int{},
		TopResources:         map[string]int{},
		TopVerbs:             map[string]int{},
		TopSources:           map[string]int{},
		TopNamespaces:        map[string]int{},
		RecentErrors:         []model.RecentError{},
		HourlyActivity:       []model.HourlyBucket{},
	}

	if err := fillTop(ctx, s.pool, fmt.Sprintf("SELECT actor, COUNT(*) FROM audit_events %s GROUP BY actor ORDER BY 2 DESC LIMIT 10", where), args, resp.TopActors); err != nil {
		return nil, err
	}
	if err := fillTop(ctx, s.pool, fmt.Sprintf("SELECT resource, COUNT(*) FROM audit_events %s GROUP BY resource ORDER BY 2 DESC LIMIT 10", where), args, resp.TopResources); err != nil {
		return nil, err
	}
	if err := fillTop(ctx, s.pool, fmt.Sprintf("SELECT verb, COUNT(*) FROM audit_events %s GROUP BY verb ORDER BY 2 DESC LIMIT 10", where), args, resp.TopVerbs); err != nil {
		return nil, err
	}
	if err := fillTop(ctx, s.pool, fmt.Sprintf("SELECT source, COUNT(*) FROM audit_events %s GROUP BY source ORDER BY 2 DESC LIMIT 10", where), args, resp.TopSources); err != nil {
		return nil, err
	}
	nsWhere := where
	if nsWhere == "" {
		nsWhere = "WHERE namespace != ''"
	} else {
		nsWhere = where + " AND namespace != ''"
	}
	if err := fillTop(ctx, s.pool, fmt.Sprintf("SELECT namespace, COUNT(*) FROM audit_events %s GROUP BY namespace ORDER BY 2 DESC LIMIT 10", nsWhere), args, resp.TopNamespaces); err != nil {
		return nil, err
	}

	errorWhere := where
	if where == "" {
		errorWhere = "WHERE result >= 400"
	} else {
		errorWhere = where + " AND result >= 400"
	}
	errorRows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT audit_id, ts, actor, verb, resource, name, namespace, result, action_summary
		FROM audit_events %s ORDER BY ts DESC LIMIT 10`, errorWhere), args...)
	if err != nil {
		return nil, err
	}
	defer errorRows.Close()
	for errorRows.Next() {
		var e model.RecentError
		var ts time.Time
		if err := errorRows.Scan(&e.AuditID, &ts, &e.Actor, &e.Verb, &e.Resource, &e.Name, &e.Namespace, &e.Result, &e.ActionSummary); err != nil {
			continue
		}
		e.Timestamp = ts.UTC().Format(time.RFC3339)
		resp.RecentErrors = append(resp.RecentErrors, e)
	}

	hourlyWhere := where
	if where == "" {
		hourlyWhere = "WHERE ts >= NOW() - INTERVAL '24 hours'"
	} else {
		hourlyWhere = where + " AND ts >= NOW() - INTERVAL '24 hours'"
	}
	hourlyRows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT
		    date_trunc('hour', ts) AS hour,
		    COUNT(*) AS total,
		    COUNT(*) FILTER (WHERE verb = 'create') AS creates,
		    COUNT(*) FILTER (WHERE verb = 'delete') AS deletes,
		    COUNT(*) FILTER (WHERE verb IN ('update','patch')) AS updates
		FROM audit_events %s
		GROUP BY hour ORDER BY hour ASC`, hourlyWhere), args...)
	if err != nil {
		return nil, err
	}
	defer hourlyRows.Close()
	for hourlyRows.Next() {
		var b model.HourlyBucket
		var ts time.Time
		if err := hourlyRows.Scan(&ts, &b.Total, &b.Creates, &b.Deletes, &b.Updates); err != nil {
			continue
		}
		b.Hour = ts.UTC().Format("15:04")
		resp.HourlyActivity = append(resp.HourlyActivity, b)
	}

	riskRow := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT
		    COUNT(*) FILTER (WHERE risk_score = 'high')   AS high,
		    COUNT(*) FILTER (WHERE risk_score = 'medium') AS medium,
		    COUNT(*) FILTER (WHERE risk_score = 'low')    AS low,
		    COUNT(*) FILTER (WHERE (risk_score = '' OR risk_score IS NULL) AND analyzed_at IS NULL) AS not_analyzed
		FROM audit_events %s`, where), args...)
	if err := riskRow.Scan(&resp.RiskHigh, &resp.RiskMedium, &resp.RiskLow, &resp.RiskNotAnalyzed); err != nil {
		return nil, fmt.Errorf("risk counts: %w", err)
	}

	riskWhere := "WHERE risk_score IN ('high','medium')"
	if where != "" {
		riskWhere = where + " AND risk_score IN ('high','medium')"
	}
	riskEventRows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT audit_id, ts, actor, verb, resource, name, namespace, risk_score, risk_reason, action_summary
		FROM audit_events %s
		ORDER BY ts DESC LIMIT 20`, riskWhere), args...)
	if err == nil {
		defer riskEventRows.Close()
		for riskEventRows.Next() {
			var e model.RiskEvent
			var ts time.Time
			if err := riskEventRows.Scan(&e.AuditID, &ts, &e.Actor, &e.Verb, &e.Resource,
				&e.Name, &e.Namespace, &e.RiskScore, &e.RiskReason, &e.ActionSummary); err != nil {
				continue
			}
			e.Timestamp = ts.UTC().Format(time.RFC3339)
			resp.TopRiskEvents = append(resp.TopRiskEvents, e)
		}
	}
	if resp.TopRiskEvents == nil {
		resp.TopRiskEvents = []model.RiskEvent{}
	}

	return resp, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotStore implementation
// ─────────────────────────────────────────────────────────────────────────────

func (s *PgStore) GetSnapshot(ctx context.Context, namespace, name string) (*model.DeploymentSnapshot, error) {
	var snap model.DeploymentSnapshot
	var containersJSON, envJSON, resourcesJSON []byte

	err := s.pool.QueryRow(ctx,
		`SELECT namespace, name, replicas, containers, env, resources FROM deployment_snapshots WHERE namespace=$1 AND name=$2`,
		namespace, name).Scan(&snap.Namespace, &snap.Name, &snap.Replicas, &containersJSON, &envJSON, &resourcesJSON)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(containersJSON, &snap.Containers); err != nil {
		snap.Containers = map[string]string{}
	}
	if err := json.Unmarshal(envJSON, &snap.Env); err != nil {
		snap.Env = map[string]string{}
	}
	if err := json.Unmarshal(resourcesJSON, &snap.Resources); err != nil {
		snap.Resources = map[string]string{}
	}
	return &snap, nil
}

func (s *PgStore) SetSnapshot(ctx context.Context, snap model.DeploymentSnapshot) error {
	containersJSON, err := json.Marshal(snap.Containers)
	if err != nil {
		return err
	}
	envJSON, err := json.Marshal(snap.Env)
	if err != nil {
		return err
	}
	resourcesJSON, err := json.Marshal(snap.Resources)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO deployment_snapshots (namespace, name, replicas, containers, env, resources, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (namespace, name)
		DO UPDATE SET replicas=$3, containers=$4, env=$5, resources=$6, updated_at=NOW()`,
		snap.Namespace, snap.Name, snap.Replicas, containersJSON, envJSON, resourcesJSON)
	return err
}

func (s *PgStore) DeleteSnapshot(ctx context.Context, namespace, name string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM deployment_snapshots WHERE namespace=$1 AND name=$2`,
		namespace, name)
	return err
}

func (s *PgStore) BulkSetSnapshots(ctx context.Context, snaps []model.DeploymentSnapshot) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, snap := range snaps {
		containersJSON, err := json.Marshal(snap.Containers)
		if err != nil {
			return err
		}
		envJSON, err := json.Marshal(snap.Env)
		if err != nil {
			return err
		}
		resourcesJSON, err := json.Marshal(snap.Resources)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO deployment_snapshots (namespace, name, replicas, containers, env, resources, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())
			ON CONFLICT (namespace, name)
			DO UPDATE SET replicas=$3, containers=$4, env=$5, resources=$6, updated_at=NOW()`,
			snap.Namespace, snap.Name, snap.Replicas, containersJSON, envJSON, resourcesJSON)
		if err != nil {
			return err
		}
	}
	log.Printf("store: upserted %d deployment snapshots", len(snaps))
	return tx.Commit(ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigMapSnapshotStore implementation
// ─────────────────────────────────────────────────────────────────────────────

func (s *PgStore) GetConfigMapSnapshot(ctx context.Context, namespace, name string) (map[string]string, error) {
	var dataJSON []byte
	err := s.pool.QueryRow(ctx,
		`SELECT data FROM configmap_snapshots WHERE namespace=$1 AND name=$2`,
		namespace, name).Scan(&dataJSON)
	if err != nil {
		return nil, err
	}
	data := map[string]string{}
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return map[string]string{}, nil
	}
	return data, nil
}

func (s *PgStore) SetConfigMapSnapshot(ctx context.Context, namespace, name string, data map[string]string) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO configmap_snapshots (namespace, name, data, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (namespace, name)
		DO UPDATE SET data=$3, updated_at=NOW()`,
		namespace, name, dataJSON)
	return err
}

func (s *PgStore) DeleteConfigMapSnapshot(ctx context.Context, namespace, name string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM configmap_snapshots WHERE namespace=$1 AND name=$2`,
		namespace, name)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// ExclusionRuleStore implementation
// ─────────────────────────────────────────────────────────────────────────────

func (s *PgStore) GetExclusionRules(ctx context.Context) ([]model.ExclusionRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, enabled, namespace, actor, actor_type, verb, resource, comment, created_at
		FROM exclusion_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []model.ExclusionRule
	for rows.Next() {
		var r model.ExclusionRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &r.Namespace,
			&r.Actor, &r.ActorType, &r.Verb, &r.Resource, &r.Comment, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []model.ExclusionRule{}
	}
	return rules, rows.Err()
}

func (s *PgStore) InsertExclusionRule(ctx context.Context, r model.ExclusionRule) (model.ExclusionRule, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO exclusion_rules (name, enabled, namespace, actor, actor_type, verb, resource, comment)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, created_at`,
		r.Name, r.Enabled, r.Namespace, r.Actor, r.ActorType, r.Verb, r.Resource, r.Comment,
	).Scan(&r.ID, &r.CreatedAt)
	return r, err
}

func (s *PgStore) UpdateExclusionRule(ctx context.Context, r model.ExclusionRule) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE exclusion_rules
		SET name=$2, enabled=$3, namespace=$4, actor=$5, actor_type=$6, verb=$7, resource=$8, comment=$9
		WHERE id=$1`,
		r.ID, r.Name, r.Enabled, r.Namespace, r.Actor, r.ActorType, r.Verb, r.Resource, r.Comment)
	return err
}

func (s *PgStore) DeleteExclusionRule(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM exclusion_rules WHERE id=$1`, id)
	return err
}

// ExclusionRuleMatch returns true if the event fields match the rule (AND logic).
// Empty rule fields match anything. Actor supports * wildcard prefix/suffix.
func ExclusionRuleMatch(r model.ExclusionRule, ns, actor, actorType, verb, resource string) bool {
	if !r.Enabled {
		return false
	}
	if r.Namespace != "" && r.Namespace != ns {
		return false
	}
	if r.ActorType != "" && r.ActorType != actorType {
		return false
	}
	if r.Resource != "" && r.Resource != resource {
		return false
	}
	// Verb: comma-separated list e.g. "get,list,watch"
	if r.Verb != "" {
		matched := false
		for _, v := range splitCommaVerbs(r.Verb) {
			if v == verb {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// Actor: exact or * wildcard
	if r.Actor != "" && !wildcardMatchActor(r.Actor, actor) {
		return false
	}
	return true
}

func wildcardMatchActor(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	return pattern == s
}

func splitCommaVerbs(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// WHERE clause builder
// ─────────────────────────────────────────────────────────────────────────────

func buildWhere(f model.EventFilter) (string, []any) {
	var conds []string
	var args []any
	n := 1

	eq := func(col, val string) {
		if val != "" {
			conds = append(conds, fmt.Sprintf("LOWER(%s) = LOWER($%d)", col, n))
			args = append(args, val)
			n++
		}
	}
	like := func(col, val string) {
		if val != "" {
			conds = append(conds, fmt.Sprintf("%s ILIKE $%d", col, n))
			args = append(args, "%"+val+"%")
			n++
		}
	}

	like("actor", f.Actor)
	like("namespace", f.Namespace)
	like("resource", f.Resource)
	eq("verb", f.Verb)
	eq("source", f.Source)
	eq("actor_type", f.ActorType)
	like("name", f.Name)

	if f.ResultCode != 0 {
		conds = append(conds, fmt.Sprintf("result = $%d", n))
		args = append(args, f.ResultCode)
		n++
	}

	if f.InterestingOnly {
		conds = append(conds, "verb = ANY('{create,update,patch,delete,deletecollection}')")
		conds = append(conds, "resource != ALL('{leases,subjectaccessreviews,selfsubjectaccessreviews,selfsubjectrulesreviews,tokenreviews}')")
	}

	if f.HideServiceAccounts {
		conds = append(conds, "actor_type NOT IN ('serviceaccount','system')")
	}

	if f.HumanOnly {
		conds = append(conds, "actor_type = 'human'")
	}

	if f.RiskScore != "" {
		if f.RiskScore == "none" {
			conds = append(conds, "(risk_score = '' OR risk_score IS NULL)")
		} else {
			conds = append(conds, fmt.Sprintf("risk_score = $%d", n))
			args = append(args, f.RiskScore)
			n++
		}
	}

	if f.From != "" {
		conds = append(conds, fmt.Sprintf("ts >= $%d", n))
		args = append(args, f.From)
		n++
	}

	if f.To != "" {
		conds = append(conds, fmt.Sprintf("ts <= $%d", n))
		args = append(args, f.To)
		n++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ─────────────────────────────────────────────────────────────────────────────
// Retention
// ─────────────────────────────────────────────────────────────────────────────

func (s *PgStore) PurgeOldEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM audit_events WHERE ts < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func fillTop(ctx context.Context, pool *pgxpool.Pool, query string, args []any, dest map[string]int) error {
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		dest[key] = count
	}
	return rows.Err()
}
