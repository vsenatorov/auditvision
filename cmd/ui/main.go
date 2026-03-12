package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"io"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/auditvision/internal/model"
	"github.com/auditvision/internal/normalize"
	"github.com/auditvision/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	dsn := mustEnv("DATABASE_URL")
	listenAddr := envOr("LISTEN_ADDR", ":8080")

	db, err := store.New(ctx, dsn)
	if err != nil {
		log.Fatalf("ui: connect to postgres: %v", err)
	}
	defer db.Close()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("ui: pgxpool connect: %v", err)
	}
	defer pool.Close()

	// Ensure alert_rules table exists (alerter may not have run yet)
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS alert_rules (
		    id           BIGSERIAL PRIMARY KEY,
		    name         TEXT NOT NULL,
		    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
		    conditions   JSONB NOT NULL DEFAULT '{}',
		    destinations TEXT[] NOT NULL DEFAULT '{email}',
		    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS alert_sent (
		    audit_id   TEXT NOT NULL,
		    reason     TEXT NOT NULL,
		    sent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    PRIMARY KEY (audit_id, reason)
		);
	`); err != nil {
		log.Printf("ui: migrate alert_rules: %v", err)
	}

	srv := &uiServer{db: db, pool: pool}

	// Auth DB migration
	if err := srv.migrateAuth(ctx); err != nil {
		log.Fatalf("ui: migrate auth: %v", err)
	}

	// Clean expired sessions in background
	go srv.cleanExpiredSessions(ctx)

	// Auto-sync OAuthClient redirectURI to current cluster Route
	go syncOAuthRedirectURI(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.healthz)
	mux.HandleFunc("/auth/login", srv.authLoginPage)
	mux.HandleFunc("/auth/ocp", srv.authOCP)
	mux.HandleFunc("/auth/basic", srv.authBasic)
	mux.HandleFunc("/auth/callback", srv.authCallback)
	mux.HandleFunc("/auth/logout", srv.authLogout)
	mux.HandleFunc("/events/", srv.authMiddleware(srv.eventByID, RoleViewer))
	mux.HandleFunc("/events", srv.authMiddleware(srv.events, RoleViewer))
	mux.HandleFunc("/summary", srv.authMiddleware(srv.summary, RoleViewer))
	mux.HandleFunc("/settings", srv.authMiddleware(srv.settings, RoleAdmin))
	mux.HandleFunc("/settings/rules", srv.authMiddleware(srv.rulesAPI, RoleEditor))
	mux.HandleFunc("/settings/rules/", srv.authMiddleware(srv.rulesAPIItem, RoleEditor))
	mux.HandleFunc("/settings/exclusions", srv.authMiddleware(srv.exclusionsAPI, RoleAdmin))
	mux.HandleFunc("/settings/exclusions/", srv.authMiddleware(srv.exclusionsAPIItem, RoleAdmin))
	mux.HandleFunc("/ui/export.csv", srv.authMiddleware(srv.exportCSV, RoleViewer))
	mux.HandleFunc("/ui/stream", srv.authMiddleware(srv.stream, RoleViewer))
	mux.HandleFunc("/ui", srv.authMiddleware(srv.ui, RoleViewer))
	mux.HandleFunc("/", srv.root)

	log.Printf("ui: listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

type uiServer struct {
	db   store.Store
	pool *pgxpool.Pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func parseFilter(r *http.Request) model.EventFilter {
	q := r.URL.Query()
	result, _ := strconv.Atoi(q.Get("result"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	parseBool := func(key string) bool {
		v := strings.ToLower(strings.TrimSpace(q.Get(key)))
		return v == "true" || v == "1" || v == "yes"
	}

	return model.EventFilter{
		Actor:               q.Get("actor"),
		Namespace:           q.Get("namespace"),
		Resource:            q.Get("resource"),
		Verb:                q.Get("verb"),
		Source:              q.Get("source"),
		ActorType:           q.Get("actorType"),
		Name:                q.Get("name"),
		ResultCode:          result,
		RiskScore:           q.Get("riskScore"),
		InterestingOnly:     parseBool("interestingOnly"),
		HideServiceAccounts: parseBool("hideServiceAccounts"),
		HumanOnly:           parseBool("humanOnly"),
		From:                parseDatetime(q.Get("from")),
		To:                  parseDatetime(q.Get("to")),
		Limit:               limit,
		Offset:              offset,
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		log.Printf("ui: write json: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

func (s *uiServer) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/ui", http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "auditvision-ui",
		"version": "0.1.0",
		"endpoints": []string{
			"/healthz",
			"/events",
			"/events/{auditID}",
			"/summary",
			"/ui",
		},
	})
}

func (s *uiServer) healthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	count, err := s.db.CountEvents(ctx, model.EventFilter{})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "totalEvents": count})
}

func (s *uiServer) events(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := parseFilter(r)
	events, err := s.db.GetEvents(ctx, f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if events == nil {
		events = []model.NormalizedEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(events),
		"events": events,
	})
}

func (s *uiServer) eventByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := strings.TrimPrefix(r.URL.Path, "/events/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	ev, err := s.db.GetEventByID(ctx, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *uiServer) summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// JSON API mode
	if r.URL.Query().Get("format") == "json" {
		f := parseFilter(r)
		sum, err := s.db.GetSummary(ctx, f)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, sum)
		return
	}
	// HTML dashboard
	f := parseFilter(r)
	sum, err := s.db.GetSummary(ctx, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sess := sessionFromContext(r.Context())
	type summaryPage struct {
		*model.SummaryResponse
		Username string
		Role     string
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := summaryTmpl.Execute(w, summaryPage{sum, sess.Username, string(sess.Role)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE stream handler — pushes new events to the browser in real time
// ─────────────────────────────────────────────────────────────────────────────

func (s *uiServer) exportCSV(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := parseFilter(r)
	f.Limit  = 10000
	f.Offset = 0

	events, err := s.db.GetEvents(ctx, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-radar-export.csv"`)
	w.Write([]byte("\xef\xbb\xbf")) // BOM for Excel UTF-8

	cw := csv.NewWriter(w)
	defer cw.Flush()

	cw.Write([]string{
		"Timestamp", "Actor", "ActorType", "Source", "SourceIP",
		"Verb", "Resource", "Subresource", "Namespace", "Name",
		"Result", "ActionSummary", "Changes", "RiskScore", "RiskReason",
	})

	for _, ev := range events {
		changes := ""
		for i, c := range ev.Changes {
			if i > 0 {
				changes += "; "
			}
			if c.Old != "" {
				changes += c.Field + ": " + c.Old + " → " + c.New
			} else {
				changes += c.Field + ": " + c.New
			}
		}
		cw.Write([]string{
			ev.Timestamp,
			ev.Actor,
			ev.ActorType,
			ev.Source,
			ev.SourceIP,
			ev.Verb,
			ev.Resource,
			ev.Subresource,
			ev.Namespace,
			ev.Name,
			strconv.Itoa(ev.Result),
			ev.ActionSummary,
			changes,
			ev.RiskScore,
			ev.RiskReason,
		})
	}
}

func (s *uiServer) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ctx := r.Context()

	// Get the latest event ID the client already has
	lastID := r.URL.Query().Get("lastID")

	// Poll DB every 2 seconds for new events newer than lastID
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Send a keep-alive comment every 15s to prevent proxy timeouts
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case <-ticker.C:
			f := parseFilter(r)
			f.Limit = 50
			f.Offset = 0
			events, err := s.db.GetEvents(ctx, f)
			if err != nil || len(events) == 0 {
				continue
			}

			// Find events newer than lastID
			var newEvents []model.NormalizedEvent
			for _, ev := range events {
				if ev.AuditID == lastID {
					break
				}
				newEvents = append(newEvents, ev)
			}
			if len(newEvents) == 0 {
				continue
			}

			// Send each new event as SSE
			for i := len(newEvents) - 1; i >= 0; i-- {
				ev := newEvents[i]
				data, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "data: %s\n\n", data)
			}
			lastID = newEvents[0].AuditID
			flusher.Flush()
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UI handler
// ─────────────────────────────────────────────────────────────────────────────

type uiTemplateData struct {
	Count    int
	Total    int
	Offset   int
	PageSize int
	Events   []model.NormalizedEvent
	Query    map[string]string
	PageNums []int
	Username string
	Role     string
}

// buildPageNums returns page numbers to show in paginator.
// Uses -1 as sentinel for "…" ellipsis.
// Always shows: first, last, current ±2, with ellipsis gaps.
func buildPageNums(current, total int) []int {
	if total <= 1 {
		return nil
	}
	show := map[int]bool{}
	for _, p := range []int{1, total, current - 2, current - 1, current, current + 1, current + 2} {
		if p >= 1 && p <= total {
			show[p] = true
		}
	}
	sorted := make([]int, 0, len(show))
	for p := 1; p <= total; p++ {
		if show[p] {
			sorted = append(sorted, p)
		}
	}
	// Insert ellipsis gaps
	result := []int{}
	for i, p := range sorted {
		if i > 0 && p-sorted[i-1] > 1 {
			result = append(result, -1)
		}
		result = append(result, p)
	}
	return result
}

func (s *uiServer) ui(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := parseFilter(r)

	// Default page size 50, allow 50/100/200
	pageSize := f.Limit
	if pageSize != 50 && pageSize != 100 && pageSize != 200 {
		pageSize = 50
	}
	f.Limit = pageSize

	events, err := s.db.GetEvents(ctx, f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []model.NormalizedEvent{}
	}

	total, err := s.db.CountEvents(ctx, f)
	if err != nil {
		total = len(events)
	}

	q := map[string]string{}
	for _, key := range []string{
		"actor", "namespace", "resource", "verb", "source",
		"actorType", "name", "result", "interestingOnly", "hideServiceAccounts", "humanOnly",
		"from", "to", "riskScore",
	} {
		q[key] = r.URL.Query().Get(key)
	}
	// Ensure checkboxes are preserved in pagination links
	for _, key := range []string{"interestingOnly", "hideServiceAccounts", "humanOnly"} {
		if q[key] == "" {
			delete(q, key)
		}
	}

	data := uiTemplateData{
		Count:    len(events),
		Total:    total,
		Offset:   f.Offset,
		PageSize: pageSize,
		Events:   events,
		Query:    q,
		PageNums: buildPageNums(f.Offset/pageSize+1, (total+pageSize-1)/pageSize),
		Username: sessionFromContext(r.Context()).Username,
		Role:     string(sessionFromContext(r.Context()).Role),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uiTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// IsInteresting and IsNoisy are re-exported here for the template.
var _ = normalize.IsInterestingVerb
var _ = normalize.IsNoisyResource

// parseDatetime converts datetime-local format (2006-01-02T15:04) to RFC3339 UTC.
func parseDatetime(s string) string {
	if s == "" {
		return ""
	}
	var t time.Time
	var err error
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		t, err = time.ParseInLocation(layout, s, time.UTC)
		if err == nil {
			break
		}
	}
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML template
// ─────────────────────────────────────────────────────────────────────────────

var uiTmpl = template.Must(template.New("ui").Funcs(template.FuncMap{
	"add":        func(a, b int) int { return a + b },
	"add1":       func(a int) int { return a + 1 },
	"subPageSize": func(pageSize, offset int) int {
		v := offset - pageSize
		if v < 0 {
			return 0
		}
		return v
	},
	"pageNum": func(pageSize, offset int) int {
		if pageSize == 0 {
			return 1
		}
		return offset/pageSize + 1
	},
	"totalPages": func(pageSize, total int) int {
		if pageSize == 0 {
			return 1
		}
		return (total + pageSize - 1) / pageSize
	},
	"pageOffset": func(pageSize, page int) int {
		return (page - 1) * pageSize
	},
	"queryString": func(q map[string]string) template.URL {
		vals := url.Values{}
		for k, v := range q {
			if v != "" {
				vals.Set(k, v)
			}
		}
		return template.URL(vals.Encode())
	},
}).Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AuditRadar</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='15' fill='%23080810'/%3E%3Ccircle cx='16' cy='16' r='11' fill='none' stroke='%233b82f6' stroke-width='0.8' stroke-opacity='0.4'/%3E%3Ccircle cx='16' cy='16' r='7' fill='none' stroke='%233b82f6' stroke-width='0.8' stroke-opacity='0.65'/%3E%3Ccircle cx='16' cy='16' r='3' fill='none' stroke='%233b82f6' stroke-width='0.8'/%3E%3Cline x1='16' y1='1' x2='16' y2='31' stroke='%233b82f6' stroke-width='0.4' stroke-opacity='0.2'/%3E%3Cline x1='1' y1='16' x2='31' y2='16' stroke='%233b82f6' stroke-width='0.4' stroke-opacity='0.2'/%3E%3Cline x1='16' y1='16' x2='27' y2='5' stroke='%23ee0000' stroke-width='2' stroke-opacity='1'/%3E%3Cline x1='16' y1='16' x2='5' y2='27' stroke='%233b82f6' stroke-width='1.5' stroke-opacity='0.9'/%3E%3Ccircle cx='24' cy='9' r='2' fill='%23ee0000'/%3E%3Ccircle cx='8' cy='24' r='1.5' fill='%233b82f6'/%3E%3C/svg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Epilogue:wght@700;800;900&family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:        #080810;
      --bg2:       #0f0f1a;
      --bg3:       #161625;
      --border:    rgba(255,255,255,0.07);
      --red:       #ff3b3b;
      --red-dim:   rgba(255,59,59,0.15);
      --red-glow:  rgba(255,59,59,0.08);
      --green:     #34d399;
      --green-dim: rgba(52,211,153,0.15);
      --yellow:    #fbbf24;
      --yellow-dim:rgba(251,191,36,0.15);
      --blue:      #3b82f6;
      --purple:    #a78bfa;
      --text:      #e2e8f0;
      --text2:     #94a3b8;
      --text3:     #64748b;
      --mono:      'JetBrains Mono', monospace;
      --sans:      'Epilogue', 'Syne', sans-serif;
    }

    /* ── LIGHT THEME ── */
    body.light {
      --bg:        #f1f5f9;
      --bg2:       #e8edf5;
      --bg3:       #dde3ee;
      --border:    rgba(0,0,0,0.08);
      --red:       #cc0000;
      --red-dim:   rgba(204,0,0,0.12);
      --red-glow:  rgba(204,0,0,0.06);
      --green:     #059669;
      --green-dim: rgba(5,150,105,0.12);
      --yellow:    #d97706;
      --yellow-dim:rgba(217,119,6,0.12);
      --blue:      #2563eb;
      --purple:    #7c3aed;
      --text:      #0f172a;
      --text2:     #334155;
      --text3:     #64748b;
    }
    body.light::before {
      background-image:
        linear-gradient(rgba(0,0,0,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,0,0,0.04) 1px, transparent 1px);
    }
    body.light table { box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    body.light tr:hover td { background: rgba(0,0,0,0.03) !important; }
    body.light .system td { background: rgba(0,0,0,0.02); }
    body.light .human-row td { background: rgba(37,99,235,0.03); }
    body.light th { color: #1e293b !important; background: #dde3ee !important; }
    body.light .nav-btn { border: 2px solid #334155 !important; color: #0f172a !important; background: #e2e8f0 !important; font-weight: 600 !important; }
    body.light .nav-btn:hover { border-color: #2563eb !important; color: #2563eb !important; background: rgba(37,99,235,0.08) !important; }
    body.light .nav-btn.active { border: 2px solid #cc0000 !important; color: #cc0000 !important; background: rgba(204,0,0,0.1) !important; font-weight: 700 !important; }
    body.light .theme-btn { border: 2px solid #334155 !important; color: #0f172a !important; background: #e2e8f0 !important; font-weight: 600 !important; }
    body.light .theme-btn:hover { border-color: #0f172a !important; background: #cbd5e1 !important; }
    body.light .refresh-btn { border: 2px solid #334155 !important; color: #0f172a !important; background: #e2e8f0 !important; font-weight: 600 !important; }
    body.light .refresh-btn.on { border: 2px solid #cc0000 !important; color: #cc0000 !important; background: rgba(204,0,0,0.08) !important; }
    body.light .toolbar { color: #334155; }
    body.light .toolbar strong { color: #0f172a; }
    body.light label { color: #1e293b; border-color: #94a3b8 !important; background: #f1f5f9 !important; }
    body.light label:hover { background: #e2e8f0 !important; }
    body.light .filters { background: #e8edf5; border-bottom-color: #cbd5e1; }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--mono);
      background: var(--bg);
      color: var(--text);
      font-size: 13px;
      min-height: 100vh;
    }

    /* ── GRID BACKGROUND ── */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(rgba(238,0,0,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(238,0,0,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
      z-index: 0;
    }

    /* ── HEADER ── */
    header {
      position: relative;
      z-index: 10;
      background: rgba(10,10,15,0.95);
      border-bottom: 1px solid var(--border);
      padding: 14px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      backdrop-filter: blur(10px);
      box-shadow: 0 1px 0 rgba(238,0,0,0.2), 0 4px 20px rgba(0,0,0,0.4);
    }
    body.light header {
      background: rgba(241,245,249,0.97);
      box-shadow: 0 1px 0 rgba(204,0,0,0.15), 0 4px 12px rgba(0,0,0,0.08);
    }
    body.light header h1 .sep { color: rgba(0,0,0,0.18); }

    .brand-wrap { display: flex; align-items: center; gap: 14px; }
    header h1 { font-family: var(--sans); font-size: 22px; font-weight: 900; letter-spacing: -0.04em; line-height: 1; }
    header h1 .audit { color: var(--red); }
    header h1 .sep   { color: rgba(255,255,255,0.15); margin: 0 2px; }
    header h1 .radar { color: var(--blue); }
    .sub { font-size: 9px; font-family: var(--mono); color: var(--text3); margin-top: 5px; letter-spacing: 2px; text-transform: uppercase; }

    .live-dot {
      width: 6px; height: 6px;
      background: var(--red);
      border-radius: 50%;
      display: inline-block;
      animation: blink 1.4s infinite;
      margin-right: 6px;
      vertical-align: middle;
      box-shadow: 0 0 6px var(--red);
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }

    .refresh-btn {
      background: transparent;
      border: 1px solid var(--text3);
      color: var(--text2);
      padding: 6px 16px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 11px;
      font-family: var(--mono);
      white-space: nowrap;
      flex-shrink: 0;
      transition: all 0.2s;
      letter-spacing: 0.5px;
    }
    .refresh-btn:hover { border-color: var(--text2); color: var(--text); }
    .refresh-btn.on {
      border-color: var(--red);
      color: var(--red);
      background: var(--red-dim);
      box-shadow: 0 0 12px rgba(238,0,0,0.2);
    }

    /* ── FILTERS ── */
    .filters {
      position: relative;
      z-index: 9;
      padding: 10px 28px;
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }

    .filters input[type="text"] {
      background: rgba(255,255,255,0.05);
      border: 1px solid #334155;
      color: #e2e8f0;
      padding: 6px 10px;
      border-radius: 5px;
      font-size: 11px;
      font-family: var(--mono);
      width: 130px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .filters input[type="text"]::placeholder { color: #94a3b8; }
    .filters input[type="text"]:focus {
      border-color: var(--red);
      box-shadow: 0 0 0 2px rgba(238,0,0,0.1);
      background: rgba(255,255,255,0.08);
    }
    body.light .filters input[type="text"] {
      background: #ffffff;
      border: 1px solid #94a3b8;
      color: #0f172a;
    }
    body.light .filters input[type="text"]::placeholder { color: #475569; }
    body.light .filters input[type="text"]:focus {
      border-color: #cc0000;
      box-shadow: 0 0 0 2px rgba(204,0,0,0.1);
    }

    label {
      font-size: 11px;
      color: #94a3b8;
      display: flex;
      align-items: center;
      gap: 7px;
      cursor: pointer;
      white-space: nowrap;
      font-family: var(--mono);
      padding: 5px 10px;
      border: 1px solid #1e293b;
      border-radius: 5px;
      background: var(--bg3);
      transition: all 0.15s;
    }
    label:hover { border-color: #64748b; color: var(--text); }
    label input[type="checkbox"] {
      appearance: none;
      -webkit-appearance: none;
      width: 13px; height: 13px;
      border: 1px solid #334155;
      border-radius: 3px;
      background: var(--bg2);
      cursor: pointer;
      position: relative;
      flex-shrink: 0;
      transition: all 0.15s;
    }
    label input[type="checkbox"]:checked {
      background: var(--red);
      border-color: var(--red);
      box-shadow: 0 0 6px rgba(238,0,0,0.4);
    }
    label input[type="checkbox"]:checked::after {
      content: '';
      position: absolute;
      left: 3px; top: 1px;
      width: 5px; height: 8px;
      border: 2px solid #fff;
      border-top: none;
      border-left: none;
      transform: rotate(45deg);
    }

    .filter-btn {
      background: var(--red);
      color: #fff;
      border: none;
      padding: 7px 18px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 700;
      font-family: var(--mono);
      letter-spacing: 0.5px;
      transition: background 0.2s, box-shadow 0.2s;
    }
    .filter-btn:hover { background: #cc0000; box-shadow: 0 0 12px rgba(238,0,0,0.3); }

    .clear-btn {
      background: transparent;
      color: var(--text2);
      border: 1px solid var(--text3);
      padding: 7px 14px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 11px;
      font-family: var(--mono);
      transition: all 0.2s;
    }
    .clear-btn:hover { border-color: var(--text2); color: var(--text); }

    /* ── RISK FILTER SELECT ── */
    .risk-filter-select {
      appearance: none;
      -webkit-appearance: none;
      background: var(--bg3);
      border: 1px solid #1e293b;
      color: var(--text2);
      padding: 6px 28px 6px 10px;
      border-radius: 5px;
      font-size: 11px;
      font-family: var(--mono);
      cursor: pointer;
      outline: none;
      transition: border-color 0.2s, color 0.2s;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%2364748b' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 8px center;
    }
    .risk-filter-select:hover { border-color: #64748b; color: var(--text); }
    .risk-filter-select:focus { border-color: var(--red); }
    /* When a risk is selected, tint the border to match */
    .risk-filter-select.sel-high   { border-color: #ef4444; color: #fca5a5; background-color: #450a0a; }
    .risk-filter-select.sel-medium { border-color: #f59e0b; color: #fcd34d; background-color: #3f2007; }
    .risk-filter-select.sel-low    { border-color: #22c55e; color: #86efac; background-color: #052e16; }
    .risk-filter-select.sel-none   { border-color: #334155; color: #64748b; }
    body.light .risk-filter-select { background-color: #f1f5f9; border-color: #94a3b8; color: #334155; }
    body.light .risk-filter-select.sel-high   { border-color: #ef4444; color: #991b1b; background-color: rgba(220,38,38,0.1); }
    body.light .risk-filter-select.sel-medium { border-color: #f59e0b; color: #92400e; background-color: rgba(245,158,11,0.1); }
    body.light .risk-filter-select.sel-low    { border-color: #22c55e; color: #14532d; background-color: rgba(34,197,94,0.1); }

    /* ── TIME RANGE PICKER ── */
    .time-range-wrap { position: relative; }
    #dateRangePicker { width: 160px; cursor: pointer; }
    .time-range-popup {
      display: none;
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      z-index: 1000;
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      padding: 14px;
      width: 280px;
    }
    .time-range-popup.open { display: block; }
    .tr-presets { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; margin-bottom: 12px; }
    .tr-preset {
      background: var(--bg2);
      border: 1px solid var(--text3);
      border-radius: 5px;
      padding: 6px 4px;
      font-size: 10px;
      font-family: var(--mono);
      cursor: pointer;
      color: var(--text2);
      transition: all 0.15s;
    }
    .tr-preset:hover { border-color: var(--red); color: var(--red); background: var(--red-glow); }
    .tr-preset.active { background: var(--red); border-color: var(--red); color: #fff; }
    .tr-today { grid-column: span 3; }
    .tr-divider { font-size: 10px; color: var(--text3); text-align: center; margin-bottom: 10px; border-top: 1px solid var(--border); padding-top: 10px; letter-spacing: 1px; }
    .tr-manual { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
    .tr-manual-row { display: flex; align-items: center; gap: 8px; }
    .tr-manual-row label { font-size: 10px; color: var(--text2); width: 28px; flex-shrink: 0; }
    .tr-manual-row input {
      flex: 1;
      background: var(--bg2);
      border: 1px solid var(--text3);
      border-radius: 4px;
      padding: 5px 7px;
      font-size: 10px;
      font-family: var(--mono);
      color: var(--text);
      outline: none;
    }
    .tr-manual-row input:focus { border-color: var(--red); }
    .tr-actions { display: flex; justify-content: space-between; }
    .tr-clear { background: transparent; border: 1px solid var(--text3); border-radius: 4px; padding: 5px 14px; font-size: 10px; font-family: var(--mono); cursor: pointer; color: var(--text2); }
    .tr-clear:hover { border-color: var(--text2); color: var(--text); }
    .tr-apply { background: var(--red); border: none; border-radius: 4px; padding: 5px 18px; font-size: 10px; font-family: var(--mono); cursor: pointer; color: #fff; font-weight: 700; }
    .tr-apply:hover { background: #cc0000; }

    /* ── TOOLBAR ── */
    .toolbar {
      position: relative;
      z-index: 8;
      padding: 8px 28px;
      font-size: 11px;
      color: #94a3b8;
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .toolbar strong { color: #e2e8f0; }

    .pagination { display: flex; align-items: center; gap: 8px; }
    .page-btn {
      display: inline-block;
      padding: 4px 12px;
      border: 1px solid var(--text3);
      border-radius: 4px;
      color: var(--text2);
      text-decoration: none;
      font-size: 11px;
      font-family: var(--mono);
      background: transparent;
      cursor: pointer;
      transition: all 0.15s;
    }
    .page-btn:hover { border-color: var(--red); color: var(--red); }
    .page-btn.disabled { color: var(--text3); border-color: var(--text3); cursor: default; pointer-events: none; }
    .page-btn.active { background: var(--red); color: #fff; border-color: var(--red); cursor: default; pointer-events: none; font-weight: 700; }
    .page-info { font-size: 11px; color: #94a3b8; padding: 0 4px; }
    .page-size-select {
      border: 1px solid var(--text3);
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 11px;
      font-family: var(--mono);
      color: var(--text2);
      background: var(--bg3);
      cursor: pointer;
      outline: none;
    }
    .page-size-select:focus { border-color: var(--red); }

    /* ── TABLE ── */
    .container {
      position: relative;
      z-index: 1;
      padding: 16px 28px;
      overflow-x: auto;
    }

    table {
      border-collapse: collapse;
      width: 100%;
      background: var(--bg2);
      border-radius: 8px;
      border: 1px solid var(--border);
      box-shadow: 0 4px 24px rgba(0,0,0,0.3);
    }

    th {
      background: var(--bg3);
      color: #94a3b8;
      text-align: left;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
      font-weight: 700;
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      font-family: var(--mono);
    }

    td {
      padding: 10px 14px;
      border-bottom: 1px solid rgba(255,255,255,0.03);
      vertical-align: top;
    }

    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(238,0,0,0.03); }

    @keyframes fadeIn {
      from { background: rgba(238,0,0,0.08); }
      to   { background: transparent; }
    }
    tr.new-event td { animation: fadeIn 2s ease-out forwards; }

    /* row left border by actor type */
    .human td:first-child         { border-left: 6px solid var(--blue); }
    .serviceaccount td:first-child { border-left: 6px solid var(--purple); }
    .system td:first-child         { border-left: 6px solid var(--text3); }

    /* ── BADGES ── */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.8px;
      font-family: var(--mono);
    }
    .verb-delete  { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
    .verb-create  { background: var(--green-dim);       color: var(--green); border: 1px solid rgba(52,211,153,0.3); }
    .verb-update  { background: var(--yellow-dim);      color: var(--yellow); border: 1px solid rgba(251,191,36,0.3); }
    .verb-patch   { background: var(--yellow-dim);      color: var(--yellow); border: 1px solid rgba(251,191,36,0.3); }
    .verb-default { background: var(--bg3);             color: var(--text2);  border: 1px solid var(--border); }
    .verb-get     { background: rgba(96,165,250,0.1);   color: #93c5fd;       border: 1px solid rgba(96,165,250,0.25); }
    .verb-list    { background: rgba(148,163,184,0.1);  color: #94a3b8;       border: 1px solid rgba(148,163,184,0.2); }
    .verb-watch   { background: rgba(167,139,250,0.1);  color: #c4b5fd;       border: 1px solid rgba(167,139,250,0.2); }

    /* ── ACTORS ── */
    .actor-human  { color: var(--blue);   font-weight: 700; font-size: 12px; }
    .actor-sa     { color: var(--purple); font-size: 11px; }
    .actor-system { color: var(--text3);  font-size: 11px; }

    .src-badge {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.14);
      color: #94a3b8;
      font-size: 9px;
      padding: 2px 7px;
      border-radius: 3px;
      font-family: var(--mono);
      letter-spacing: 0.5px;
      font-weight: 500;
    }

    /* ── CELLS ── */
    .summary   { color: var(--text); font-size: 11px; }
    .changes   { color: var(--text2); }
    .change-row { margin-bottom: 3px; line-height: 1.6; }
    .field     { color: var(--yellow); font-size: 10px; font-family: var(--mono); }
    .old-val   { color: var(--text3); text-decoration: line-through; font-family: var(--mono); font-size: 10px; }
    .arrow     { color: var(--text3); margin: 0 3px; }
    .new-val   { color: var(--green); font-weight: 700; font-family: var(--mono); font-size: 10px; }
    .result-ok  { color: var(--green);  font-weight: 700; font-size: 11px; }
    .result-err { color: #f87171;       font-weight: 700; font-size: 11px; }
    .ts        { color: var(--text2); font-size: 10px; white-space: nowrap; font-family: var(--mono); }
    .ns        { color: var(--text2); font-size: 11px; font-family: var(--mono); }
    .name-cell { color: var(--text);  font-family: var(--mono); font-size: 11px; }
    a { color: #64748b; text-decoration: none; font-size: 10px; font-family: var(--mono); transition: color 0.15s; }
    a:hover { color: var(--red); }
    td a { color: #64748b; border: 1px solid #1e293b; padding: 1px 6px; border-radius: 3px; background: rgba(255,255,255,0.03); }
    td a:hover { color: var(--red); border-color: rgba(238,0,0,0.3); background: var(--red-glow); }

    /* ── NAV ── */
    .nav-btn {
      display: inline-block;
      padding: 6px 16px;
      border: 1px solid var(--text2);
      border-radius: 5px;
      color: var(--text);
      text-decoration: none;
      font-size: 11px;
      font-family: var(--mono);
      font-weight: 500;
      letter-spacing: 0.5px;
      transition: all 0.15s;
      background: transparent;
    }
    .nav-btn:hover { border-color: var(--blue); color: var(--blue); background: rgba(59,130,246,0.08); }
    .nav-btn.active { border-color: var(--red); color: var(--red); background: var(--red-dim); }
    td .nav-btn { font-size: 11px; border: none; padding: 0; background: transparent; }

    .theme-btn {
      background: transparent;
      border: 1px solid var(--text2);
      border-radius: 5px;
      color: var(--text);
      font-family: var(--mono);
      font-size: 11px;
      padding: 6px 12px;
      cursor: pointer;
      transition: all 0.15s;
      letter-spacing: 0.5px;
    }
    .theme-btn:hover { border-color: var(--text2); color: var(--text); }

    /* ── RISK BADGES (table column) ── */
    .risk-badge  { font-family: var(--mono); font-size: 9px; font-weight: 800; white-space: nowrap; letter-spacing: 0.08em; transition: opacity 0.15s; cursor: default; }
    .risk-high, .risk-medium, .risk-low { cursor: pointer; }
    .risk-high:hover, .risk-medium:hover, .risk-low:hover { opacity: 0.75; }
    .risk-high   { color: #fca5a5; background: #450a0a; border: 1px solid #ef4444; padding: 1px 5px; border-radius: 2px; }
    .risk-medium { color: #fcd34d; background: #3f2007; border: 1px solid #f59e0b; padding: 1px 5px; border-radius: 2px; }
    .risk-low    { color: #86efac; background: #052e16; border: 1px solid #22c55e; padding: 1px 5px; border-radius: 2px; }
    .risk-none   { color: #64748b; background: #1e293b; border: 1px solid #334155; padding: 1px 5px; border-radius: 2px; }
    .risk-bar        { font-family: var(--mono); font-size: 9px; font-weight: 800; letter-spacing: 0.08em; padding: 1px 5px; border-radius: 2px; }
    .risk-bar-high   { color: #fca5a5; background: #450a0a; border: 1px solid #ef4444; }
    .risk-bar-medium { color: #fcd34d; background: #3f2007; border: 1px solid #f59e0b; }
    .sq-badge        { font-family: var(--mono); font-size: 9px; font-weight: 800; letter-spacing: 0.08em; padding: 1px 6px; border-radius: 2px; }
    .sq-high         { color: #fca5a5; background: #450a0a; border: 1px solid #ef4444; }
    .sq-medium       { color: #fcd34d; background: #3f2007; border: 1px solid #f59e0b; }
    .sq-low          { color: #86efac; background: #052e16; border: 1px solid #22c55e; }
    .sq-none         { color: #64748b; background: #1e293b; border: 1px solid #334155; }
    body.light .risk-high   { color: #991b1b; background: rgba(220,38,38,0.1);  border-color: #ef4444; }
    body.light .risk-medium { color: #92400e; background: rgba(245,158,11,0.1); border-color: #f59e0b; }
    body.light .risk-low    { color: #14532d; background: rgba(34,197,94,0.1);  border-color: #22c55e; }
    body.light .risk-none   { color: #64748b; background: rgba(100,116,139,0.1);border-color: #94a3b8; }
    body.light .sq-high     { color: #991b1b; background: rgba(220,38,38,0.1);  border-color: #ef4444; }
    body.light .sq-medium   { color: #92400e; background: rgba(245,158,11,0.1); border-color: #f59e0b; }
    body.light .sq-low      { color: #14532d; background: rgba(34,197,94,0.1);  border-color: #22c55e; }
    body.light .sq-none     { color: #64748b; background: rgba(100,116,139,0.1);border-color: #94a3b8; }

    .risk-popup {
      position: fixed;
      z-index: 9999;
      max-width: 340px;
      background: #0e0e1e;
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 4px;
      padding: 12px 14px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6);
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.6;
      color: var(--text);
      display: none;
      pointer-events: auto;
    }
    .risk-popup.visible { display: block; }
    .risk-popup-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.07); }
    .risk-popup-title { font-weight: 700; font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text2); }
    .risk-popup-close { cursor: pointer; color: var(--text3); font-size: 14px; line-height: 1; padding: 0 2px; }
    .risk-popup-close:hover { color: var(--text); }
    .risk-popup-body { color: var(--text); font-size: 11px; line-height: 1.7; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }
    .risk-popup-copy { margin-top: 10px; text-align: right; }
    .risk-copy-btn { background: transparent; border: 1px solid var(--text3); border-radius: 3px; padding: 3px 12px; font-size: 10px; font-family: var(--mono); cursor: pointer; color: var(--text2); }
    .risk-copy-btn:hover { border-color: var(--text2); color: var(--text); }
    .risk-copy-btn.copied { border-color: var(--green); color: var(--green); }
    .risk-i { font-size: 9px; opacity: 0.7; }
    .risk-pending { color: #f59e0b; background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); padding: 1px 5px; border-radius: 2px; letter-spacing: 0.1em; }
    body.light .risk-popup { background: #f0f4ff; border-color: #94a3b8; color: #1e2f50; }

    .export-btn {
      display: inline-block;
      padding: 4px 12px;
      border: 1px solid rgba(96,165,250,0.5);
      border-radius: 4px;
      color: var(--blue);
      text-decoration: none;
      font-size: 11px;
      font-family: var(--mono);
      transition: all 0.15s;
    }
    .export-btn:hover { border-color: var(--blue); }

    /* ── SCROLLBAR ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--text3); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text2); }
  </style>
</head>
<body>
<header>
  <a href="/ui" class="brand-wrap" style="text-decoration:none;">
    <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32' width="38" height="38" style="flex-shrink:0;filter:drop-shadow(0 0 10px rgba(100,130,255,0.4))">
      <circle cx='16' cy='16' r='15' fill='#080810'/>
      <circle cx='16' cy='16' r='11' fill='none' stroke='#3b82f6' stroke-width='0.8' stroke-opacity='0.45'/>
      <circle cx='16' cy='16' r='7'  fill='none' stroke='#3b82f6' stroke-width='0.8' stroke-opacity='0.75'/>
      <circle cx='16' cy='16' r='3'  fill='none' stroke='#aab4c8' stroke-width='0.8'/>
      <line x1='16' y1='1' x2='16' y2='31' stroke='#3b82f6' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='1'  y1='16' x2='31' y2='16' stroke='#3b82f6' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='16' y1='16' x2='27' y2='5'  stroke='#ee0000' stroke-width='2'   stroke-opacity='1' stroke-linecap='round'/>
      <line x1='16' y1='16' x2='5'  y2='27' stroke='#3b82f6' stroke-width='1.5' stroke-opacity='0.9' stroke-linecap='round'/>
      <circle cx='24' cy='9'  r='2.2' fill='#ee0000'/>
      <circle cx='8'  cy='24' r='1.8' fill='#3b82f6'/>
    </svg>
    <div>
      <h1><span class="audit">audit</span><span class="sep">·</span><span class="radar">radar</span></h1>
      <div class="sub"><span class="live-dot"></span>real-time audit explorer</div>
    </div>
  </a>
  <div style="display:flex;align-items:center;gap:12px;">
    <nav style="display:flex;gap:4px;">
      <a href="/ui"      class="nav-btn nav-active-check" data-page="ui">Events</a>
      <a href="/summary" class="nav-btn nav-active-check" data-page="summary">Summary</a>
      <a href="/settings" class="nav-btn nav-active-check" data-page="settings">Settings</a>
    </nav>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀ light</button>
    <button class="refresh-btn on" id="refreshBtn" onclick="toggleStream()">⏸ live: on</button>
    {{if .Username}}
    <div style="display:flex;align-items:center;gap:8px;padding:4px 10px;border:1px solid rgba(255,255,255,0.1);border-radius:5px;font-size:10px;font-family:var(--mono);">
      <span style="color:var(--text3);">{{if eq .Role "admin"}}⬡{{else if eq .Role "editor"}}◈{{else}}◇{{end}}</span>
      <span style="color:var(--text2);">{{.Username}}</span>
      <span style="font-size:9px;padding:1px 6px;border-radius:2px;font-weight:700;letter-spacing:0.08em;
        {{if eq .Role "admin"}}background:rgba(255,59,59,0.15);color:#ff8080;border:1px solid rgba(255,59,59,0.3);
        {{else if eq .Role "editor"}}background:rgba(59,130,246,0.15);color:#93c5fd;border:1px solid rgba(59,130,246,0.3);
        {{else}}background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.3);{{end}}">{{.Role}}</span>
      <a href="/auth/logout" style="color:var(--text3);font-size:10px;font-family:var(--mono);text-decoration:none;padding:2px 6px;border-radius:3px;border:1px solid rgba(255,255,255,0.07);transition:all 0.15s;" onmouseover="this.style.color='#f87171';this.style.borderColor='rgba(248,113,113,0.3)'" onmouseout="this.style.color='';this.style.borderColor=''">exit</a>
    </div>
    {{end}}
  </div>
</header>
<script>
  (function() {
    var path = window.location.pathname;
    document.querySelectorAll('.nav-btn').forEach(function(a) {
      if (a.getAttribute('href') === path) a.classList.add('active');
    });
  })();

  function toggleTheme() {
    var body = document.body;
    var btn = document.getElementById('themeBtn');
    if (body.classList.contains('light')) {
      body.classList.remove('light');
      btn.textContent = '\u2600 light';
      localStorage.setItem('theme', 'dark');
    } else {
      body.classList.add('light');
      btn.textContent = '\u25d1 dark';
      localStorage.setItem('theme', 'light');
    }
  }
  (function() {
    if (localStorage.getItem('theme') === 'light') {
      document.body.classList.add('light');
      var btn = document.getElementById('themeBtn');
      if (btn) btn.textContent = '\u25d1 dark';
    }
  })();

  var evtSource = null;
  var streaming = false;

  function getLastID() {
    var links = document.querySelectorAll('tr[data-audit-id]');
    if (links.length > 0) return links[0].getAttribute('data-audit-id');
    return '';
  }

  function formatTS(raw) {
    if (!raw) return '';
    var d = new Date(raw);
    if (isNaN(d)) return raw;
    var pad = function(n){ return String(n).padStart(2,'0'); };
    return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) +
           ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function verbClass(verb) {
    switch((verb||'').toLowerCase()) {
      case 'delete': return 'verb-delete';
      case 'create': return 'verb-create';
      case 'update': return 'verb-update';
      case 'patch':  return 'verb-patch';
      case 'get':    return 'verb-get';
      case 'list':   return 'verb-list';
      case 'watch':  return 'verb-watch';
      default:       return 'verb-default';
    }
  }

  function riskClass(score) {
    switch((score||'').toLowerCase()) {
      case 'high':   return 'risk-badge risk-high';
      case 'medium': return 'risk-badge risk-medium';
      case 'low':    return 'risk-badge risk-low';
      default:       return 'risk-badge risk-none';
    }
  }

  function riskLabel(score, verb) {
    switch((score||'').toLowerCase()) {
      case 'high':   return 'HIGH <span class="risk-i">i</span>';
      case 'medium': return 'MED <span class="risk-i">i</span>';
      case 'low':    return 'LOW <span class="risk-i">i</span>';
      default:
        var v = (verb||'').toLowerCase();
        if (v === 'get' || v === 'list' || v === 'watch') return 'SKIP';
        return '&middot;&middot;&middot;';
    }
  }

  function renderChanges(changes) {
    if (!changes || changes.length === 0) return '';
    return changes.map(function(c) {
      var html = '<div class="change-row"><span class="field">' + escHtml(c.field) + '</span>';
      if (c.old) html += '<span class="old-val"> ' + escHtml(c.old) + '</span><span class="arrow"> -&gt;</span>';
      html += '<span class="new-val"> ' + escHtml(c.new) + '</span></div>';
      return html;
    }).join('');
  }

  function escHtml(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function renderRow(ev) {
    var actorClass = ev.actorType === 'human' ? 'actor-human' : ev.actorType === 'serviceaccount' ? 'actor-sa' : 'actor-system';
    var resultClass = (ev.result||0) < 400 ? 'result-ok' : 'result-err';
    var rc = riskClass(ev.riskScore);
    var rl = riskLabel(ev.riskScore, ev.verb);
    var riskClickable = (ev.riskScore === 'high' || ev.riskScore === 'medium' || ev.riskScore === 'low');
    var riskOnClick = riskClickable ? ' onclick="showRisk(this)" data-reason="' + escHtml(ev.riskReason||'') + '"' : '';
    return '<tr class="' + escHtml(ev.actorType) + ' new-event" data-audit-id="' + escHtml(ev.auditID) + '">' +
      '<td class="ts">' + formatTS(ev.timestamp) + '</td>' +
      '<td><span class="' + actorClass + '">' + escHtml(ev.actor) + '</span></td>' +
      '<td><span class="src-badge">' + escHtml(ev.source) + '</span></td>' +
      '<td><span class="badge ' + verbClass(ev.verb) + '">' + escHtml((ev.verb||'').toUpperCase()) + '</span></td>' +
      '<td class="ns">' + escHtml(ev.namespace) + '</td>' +
      '<td class="name-cell">' + escHtml(ev.resource) + (ev.name ? '/' + escHtml(ev.name) : '') + (ev.subresource ? '/' + escHtml(ev.subresource) : '') + '</td>' +
      '<td class="summary">' + escHtml(ev.actionSummary) + '</td>' +
      '<td class="changes">' + renderChanges(ev.changes) + '</td>' +
      '<td><span class="' + resultClass + '">' + (ev.result||'') + '</span></td>' +
      '<td><span class="' + rc + '"' + riskOnClick + '>' + rl + '</span></td>' +
      '<td><a href="/events/' + escHtml(ev.auditID) + '" target="_blank">JSON</a></td>' +
      '</tr>';
  }

  var seenAuditIDs = new Set();

  function startStream() {
    if (evtSource) evtSource.close();
    var params = new URLSearchParams(window.location.search);
    params.set('lastID', getLastID());
    evtSource = new EventSource('/ui/stream?' + params.toString());
    evtSource.onmessage = function(e) {
      var ev = JSON.parse(e.data);
      if (seenAuditIDs.has(ev.auditID)) return;
      seenAuditIDs.add(ev.auditID);
      var tbody = document.querySelector('tbody');
      tbody.insertAdjacentHTML('afterbegin', renderRow(ev));
      var strongs = document.querySelectorAll('.toolbar span strong');
      if (strongs.length >= 2) {
        var cur = parseInt(strongs[1].textContent || '0');
        strongs[1].textContent = cur + 1;
        var range = strongs[0].textContent.split('–');
        if (range.length === 2) strongs[0].textContent = range[0] + '–' + (parseInt(range[1]||'0') + 1);
      }
      setTimeout(function() {
        var row = tbody.querySelector('.new-event');
        if (row) row.classList.remove('new-event');
      }, 2000);
    };
    evtSource.onerror = function() {};
  }

  function stopStream() {
    if (evtSource) { evtSource.close(); evtSource = null; }
  }

  function toggleStream() {
    var btn = document.getElementById('refreshBtn');
    if (streaming) {
      stopStream();
      streaming = false;
      btn.innerHTML = '⏹ live: off';
      btn.classList.remove('on');
      sessionStorage.setItem('liveStream', 'off');
    } else {
      startStream();
      streaming = true;
      btn.innerHTML = '⏸ live: on';
      btn.classList.add('on');
      sessionStorage.setItem('liveStream', 'on');
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('tbody tr[data-audit-id]').forEach(function(row) {
      seenAuditIDs.add(row.getAttribute('data-audit-id'));
    });
    var btn = document.getElementById('refreshBtn');
    var savedState = sessionStorage.getItem('liveStream');
    if (savedState !== 'off') {
      startStream();
      streaming = true;
      if (btn) { btn.innerHTML = '⏸ live: on'; btn.classList.add('on'); }
    } else {
      if (btn) { btn.innerHTML = '⏹ live: off'; btn.classList.remove('on'); }
    }
    // Apply risk select tint on load
    updateRiskSelectStyle();
  });

  // Tint the risk select to match chosen risk level
  function updateRiskSelectStyle() {
    var sel = document.querySelector('.risk-filter-select');
    if (!sel) return;
    sel.classList.remove('sel-high','sel-medium','sel-low','sel-none');
    if (sel.value === 'high')   sel.classList.add('sel-high');
    if (sel.value === 'medium') sel.classList.add('sel-medium');
    if (sel.value === 'low')    sel.classList.add('sel-low');
    if (sel.value === 'none')   sel.classList.add('sel-none');
  }
</script>
<form method="get" action="/ui" id="filterForm">
<div class="filters">
  <input type="text" name="actor"     placeholder="actor"         value="{{index .Query "actor"}}">
  <input type="text" name="namespace" placeholder="namespace"     value="{{index .Query "namespace"}}">
  <input type="text" name="resource"  placeholder="resource"      value="{{index .Query "resource"}}">
  <input type="text" name="verb"      placeholder="verb"          value="{{index .Query "verb"}}">
  <input type="text" name="source"    placeholder="source"        value="{{index .Query "source"}}">
  <input type="text" name="actorType" placeholder="actorType"     value="{{index .Query "actorType"}}">
  <input type="text" name="name"      placeholder="resource name" value="{{index .Query "name"}}">
  <input type="text" name="result"    placeholder="result code"   value="{{index .Query "result"}}">
  <input type="hidden" name="from" id="fromInput" value="{{index .Query "from"}}">
  <input type="hidden" name="to"   id="toInput"   value="{{index .Query "to"}}">
  <div class="time-range-wrap">
    <input type="text" id="dateRangePicker" placeholder="&#128337; time range" readonly>
    <div class="time-range-popup" id="timePopup">
      <div class="tr-presets">
        <button type="button" class="tr-preset" onclick="setPreset(15)">Last 15m</button>
        <button type="button" class="tr-preset" onclick="setPreset(60)">Last 1h</button>
        <button type="button" class="tr-preset" onclick="setPreset(360)">Last 6h</button>
        <button type="button" class="tr-preset" onclick="setPreset(1440)">Last 24h</button>
        <button type="button" class="tr-preset" onclick="setPreset(10080)">Last 7d</button>
        <button type="button" class="tr-preset tr-today" onclick="setToday()">Today</button>
      </div>
      <div class="tr-divider">or enter manually (local time)</div>
      <div class="tr-manual">
        <div class="tr-manual-row">
          <label>From</label>
          <input type="datetime-local" id="manualFrom">
        </div>
        <div class="tr-manual-row">
          <label>To</label>
          <input type="datetime-local" id="manualTo">
        </div>
      </div>
      <div class="tr-actions">
        <button type="button" class="tr-clear" onclick="clearRange()">Clear</button>
        <button type="button" class="tr-apply" onclick="applyRange()">Apply</button>
      </div>
    </div>
  </div>
  <select name="riskScore" class="risk-filter-select" onchange="updateRiskSelectStyle()">
    <option value=""       {{if eq (index .Query "riskScore") ""}}      selected{{end}}>all risks</option>
    <option value="high"   {{if eq (index .Query "riskScore") "high"}}  selected{{end}}>HIGH</option>
    <option value="medium" {{if eq (index .Query "riskScore") "medium"}}selected{{end}}>MED</option>
    <option value="low"    {{if eq (index .Query "riskScore") "low"}}   selected{{end}}>LOW</option>
    <option value="none"   {{if eq (index .Query "riskScore") "none"}}  selected{{end}}>— not analyzed</option>
  </select>
  <label><input type="checkbox" name="interestingOnly"     value="true" {{if eq (index .Query "interestingOnly")     "true"}}checked{{end}}> mutations only</label>
  <label><input type="checkbox" name="hideServiceAccounts" value="true" {{if eq (index .Query "hideServiceAccounts") "true"}}checked{{end}}> hide SAs</label>
  <label><input type="checkbox" name="humanOnly"           value="true" {{if eq (index .Query "humanOnly")           "true"}}checked{{end}}> humans only</label>
  <button class="filter-btn" type="submit">Filter</button>
  <button class="clear-btn" type="button" onclick="window.location='/ui'">Clear</button>
</div>
</form>
<div class="toolbar">
  <span>Showing <strong>{{.Offset | add1}}–{{.Offset | add .Count}}</strong> of <strong>{{.Total}}</strong> events</span>
  <div style="display:flex;align-items:center;gap:8px;">
    <a class="export-btn" href="/ui/export.csv?{{.Query | queryString}}&limit=10000&offset=0" title="Export current filter to CSV">⬇ CSV</a>
    <div class="pagination">
    {{$prevOffset := .Offset | subPageSize .PageSize}}
    {{$nextOffset := .Offset | add .PageSize}}
    {{$currentPage := .Offset | pageNum .PageSize}}
    {{$totalPages := .Total | totalPages .PageSize}}
    {{if gt .Offset 0}}
      <a class="page-btn" href="?{{.Query | queryString}}&limit={{.PageSize}}&offset={{$prevOffset}}">&#8592;</a>
    {{else}}
      <span class="page-btn disabled">&#8592;</span>
    {{end}}
    {{range .PageNums}}
      {{if eq . -1}}
        <span class="page-btn disabled">…</span>
      {{else if eq . $currentPage}}
        <span class="page-btn active">{{.}}</span>
      {{else}}
        <a class="page-btn" href="?{{$.Query | queryString}}&limit={{$.PageSize}}&offset={{. | pageOffset $.PageSize}}">{{.}}</a>
      {{end}}
    {{end}}
    {{if lt $nextOffset .Total}}
      <a class="page-btn" href="?{{.Query | queryString}}&limit={{.PageSize}}&offset={{$nextOffset}}">&#8594;</a>
    {{else}}
      <span class="page-btn disabled">&#8594;</span>
    {{end}}
    <select class="page-size-select" onchange="changePageSize(this.value)">
      <option value="50"  {{if eq .PageSize 50}}selected{{end}}>50 / page</option>
      <option value="100" {{if eq .PageSize 100}}selected{{end}}>100 / page</option>
      <option value="200" {{if eq .PageSize 200}}selected{{end}}>200 / page</option>
    </select>
  </div>
  </div>
</div>
<div class="container">
<table>
  <thead><tr>
    <th>Time</th><th>Actor</th><th>Source</th><th>Verb</th>
    <th>Namespace</th><th>Resource / Name</th><th>Action</th>
    <th>Changes</th><th>Result</th><th>Risk</th><th></th>
  </tr></thead>
  <tbody>
  {{range .Events}}
  <tr class="{{.ActorType}}" data-audit-id="{{.AuditID}}">
    <td class="ts" data-ts="{{.Timestamp}}"></td>
    <td>
      {{if eq .ActorType "human"}}<span class="actor-human">{{.Actor}}</span>
      {{else if eq .ActorType "serviceaccount"}}<span class="actor-sa">{{.Actor}}</span>
      {{else}}<span class="actor-system">{{.Actor}}</span>{{end}}
    </td>
    <td><span class="src-badge">{{.Source}}</span></td>
    <td>
      {{if eq .Verb "delete"}}<span class="badge verb-delete">DELETE</span>
      {{else if eq .Verb "create"}}<span class="badge verb-create">CREATE</span>
      {{else if eq .Verb "update"}}<span class="badge verb-update">UPDATE</span>
      {{else if eq .Verb "patch"}}<span class="badge verb-patch">PATCH</span>
      {{else if eq .Verb "get"}}<span class="badge verb-get">GET</span>
      {{else if eq .Verb "list"}}<span class="badge verb-list">LIST</span>
      {{else if eq .Verb "watch"}}<span class="badge verb-watch">WATCH</span>
      {{else}}<span class="badge verb-default">{{.Verb}}</span>{{end}}
    </td>
    <td class="ns">{{.Namespace}}</td>
    <td class="name-cell">{{.Resource}}{{if .Name}}/{{.Name}}{{end}}{{if .Subresource}}/{{.Subresource}}{{end}}</td>
    <td class="summary">{{.ActionSummary}}</td>
    <td class="changes">
      {{range .Changes}}
      <div class="change-row">
        <span class="field">{{.Field}}</span>
        {{if .Old}}<span class="old-val"> {{.Old}}</span><span class="arrow"> -&gt;</span>{{end}}
        <span class="new-val"> {{.New}}</span>
      </div>
      {{end}}
    </td>
    <td>
      {{if lt .Result 400}}<span class="result-ok">{{.Result}}</span>
      {{else}}<span class="result-err">{{.Result}}</span>{{end}}
    </td>
    <td>
      {{if eq .RiskScore "high"}}
        <span class="risk-badge risk-high" onclick="showRisk(this)" data-reason="{{.RiskReason}}">HIGH <span class="risk-i">ℹ</span></span>
      {{else if eq .RiskScore "medium"}}
        <span class="risk-badge risk-medium" onclick="showRisk(this)" data-reason="{{.RiskReason}}">MED <span class="risk-i">ℹ</span></span>
      {{else if eq .RiskScore "low"}}
        <span class="risk-badge risk-low" onclick="showRisk(this)" data-reason="{{.RiskReason}}">LOW <span class="risk-i">ℹ</span></span>
      {{else if or (eq .Verb "get") (eq .Verb "list") (eq .Verb "watch")}}
        <span class="risk-badge risk-none" title="GET/LIST/WATCH events are not analyzed">SKIP</span>
      {{else}}<span class="risk-badge risk-pending" title="Pending analysis by IBM Granite 3.2">···</span>{{end}}
    </td>
    <td><a href="/events/{{.AuditID}}" target="_blank">JSON</a></td>
  </tr>
  {{end}}
  </tbody>
</table>
</div>
<script>
  document.querySelectorAll('td[data-ts]').forEach(function(td) {
    var raw = td.getAttribute('data-ts');
    if (!raw) return;
    var d = new Date(raw);
    if (isNaN(d)) { td.textContent = raw; return; }
    var pad = function(n){ return String(n).padStart(2,'0'); };
    td.textContent =
      d.getFullYear() + '-' +
      pad(d.getMonth()+1) + '-' +
      pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' +
      pad(d.getMinutes()) + ':' +
      pad(d.getSeconds());
    td.title = raw;
  });

  function changePageSize(size) {
    var url = new URL(window.location.href);
    url.searchParams.set('limit', size);
    url.searchParams.set('offset', '0');
    window.location.href = url.toString();
  }

  // ── Time range picker ──────────────────────────────────────────────────────
  var picker = document.getElementById('dateRangePicker');
  var popup  = document.getElementById('timePopup');

  picker.addEventListener('click', function(e) {
    e.stopPropagation();
    popup.classList.toggle('open');
    var from = document.getElementById('fromInput').value;
    var to   = document.getElementById('toInput').value;
    if (from) document.getElementById('manualFrom').value = from.slice(0,16);
    if (to)   document.getElementById('manualTo').value   = to.slice(0,16);
  });

  document.addEventListener('click', function(e) {
    if (!popup.contains(e.target) && e.target !== picker) {
      popup.classList.remove('open');
    }
  });

  var pad = function(n){ return String(n).padStart(2,'0'); };

  function fmtUTC(d) {
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth()+1) + '-' + pad(d.getUTCDate()) +
           'T' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes());
  }

  function fmtDisplay(d) {
    return pad(d.getDate()) + '/' + pad(d.getMonth()+1) + '/' + d.getFullYear() +
           ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function setRange(from, to, label) {
    document.getElementById('fromInput').value = fmtUTC(from);
    document.getElementById('toInput').value   = fmtUTC(to);
    picker.value = label || (fmtDisplay(from) + ' → ' + fmtDisplay(to));
    document.querySelectorAll('.tr-preset').forEach(function(b){ b.classList.remove('active'); });
  }

  function setPreset(minutes) {
    var to   = new Date();
    var from = new Date(to.getTime() - minutes * 60000);
    var labels = {15:'Last 15m', 60:'Last 1h', 360:'Last 6h', 1440:'Last 24h', 10080:'Last 7d'};
    setRange(from, to, labels[minutes]);
    document.querySelectorAll('.tr-preset').forEach(function(b){
      if (b.textContent.trim() === labels[minutes]) b.classList.add('active');
    });
    popup.classList.remove('open');
    document.getElementById('filterForm').submit();
  }

  function setToday() {
    var now  = new Date();
    var from = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0);
    setRange(from, now, 'Today');
    popup.classList.remove('open');
    document.getElementById('filterForm').submit();
  }

  function applyRange() {
    var fromVal = document.getElementById('manualFrom').value;
    var toVal   = document.getElementById('manualTo').value;
    if (!fromVal && !toVal) { clearRange(); return; }
    if (fromVal) {
      var f = new Date(fromVal);
      document.getElementById('fromInput').value = fmtUTC(f);
    }
    if (toVal) {
      var t = new Date(toVal);
      document.getElementById('toInput').value = fmtUTC(t);
    }
    var parts = [];
    if (fromVal) parts.push(fmtDisplay(new Date(fromVal)));
    if (toVal)   parts.push(fmtDisplay(new Date(toVal)));
    picker.value = parts.join(' → ');
    popup.classList.remove('open');
    document.getElementById('filterForm').submit();
  }

  function clearRange() {
    document.getElementById('fromInput').value = '';
    document.getElementById('toInput').value   = '';
    document.getElementById('manualFrom').value = '';
    document.getElementById('manualTo').value   = '';
    picker.value = '';
    popup.classList.remove('open');
  }

  (function() {
    var from = document.getElementById('fromInput').value;
    var to   = document.getElementById('toInput').value;
    if (from || to) {
      var parts = [];
      if (from) parts.push(fmtDisplay(new Date(from)));
      if (to)   parts.push(fmtDisplay(new Date(to)));
      picker.value = parts.join(' → ');
    }
  })();
</script>
<div id="riskPopup" class="risk-popup">
  <div class="risk-popup-header">
    <span class="risk-popup-title">AI Risk Assessment</span>
    <span class="risk-popup-close" onclick="closeRisk()">✕</span>
  </div>
  <div class="risk-popup-body" id="riskPopupBody"></div>
  <div class="risk-popup-copy">
    <button class="risk-copy-btn" id="riskCopyBtn" onclick="copyRisk()">Copy</button>
  </div>
</div>
<script>
  var riskPopup  = document.getElementById('riskPopup');
  var riskBody   = document.getElementById('riskPopupBody');
  var riskCopyBtn= document.getElementById('riskCopyBtn');
  var currentReason = '';

  function showRisk(el) {
    currentReason = el.getAttribute('data-reason') || 'No explanation available.';
    riskBody.textContent = currentReason;
    riskCopyBtn.textContent = 'Copy';
    riskCopyBtn.classList.remove('copied');
    var rect = el.getBoundingClientRect();
    var popupW = 340, popupH = 220, margin = 12;
    var left = rect.left, top = rect.bottom + 6;
    if (left + popupW > window.innerWidth - margin) left = window.innerWidth - popupW - margin;
    if (left < margin) left = margin;
    if (top + popupH > window.innerHeight - margin) top = rect.top - popupH - 6;
    if (top < margin) top = margin;
    riskPopup.style.left = left + 'px';
    riskPopup.style.top  = top + 'px';
    riskPopup.classList.add('visible');
  }
  function closeRisk() { riskPopup.classList.remove('visible'); }
  function copyRisk() {
    navigator.clipboard.writeText(currentReason).then(function() {
      riskCopyBtn.textContent = 'Copied!';
      riskCopyBtn.classList.add('copied');
      setTimeout(function(){ riskCopyBtn.textContent = 'Copy'; riskCopyBtn.classList.remove('copied'); }, 2000);
    });
  }
  document.addEventListener('click', function(e) {
    if (riskPopup && !riskPopup.contains(e.target) &&
        !e.target.classList.contains('risk-high') &&
        !e.target.classList.contains('risk-medium') &&
        !e.target.classList.contains('risk-low') &&
        !e.target.classList.contains('risk-i') &&
        !e.target.closest('.risk-badge')) {
      closeRisk();
    }
  });
</script>
</body>
</html>
`))

// ─────────────────────────────────────────────────────────────────────────────
// Summary template — unchanged from original
// ─────────────────────────────────────────────────────────────────────────────

var summaryTmpl = template.Must(template.New("summary").Funcs(template.FuncMap{
	"fmtTime": func(s string) string {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return s
		}
		return t.Format("01-02 15:04:05")
	},
	"pct": func(part, total int) int {
		if total == 0 {
			return 0
		}
		return part * 100 / total
	},
	"verbColor": func(verb string) string {
		switch verb {
		case "delete":
			return "#f87171"
		case "create":
			return "#34d399"
		case "update", "patch":
			return "#fbbf24"
		case "get":
			return "#60a5fa"
		case "list":
			return "#94a3b8"
		case "watch":
			return "#c4b5fd"
		default:
			return "#64748b"
		}
	},
	"verbBg": func(verb string) string {
		switch verb {
		case "delete":
			return "rgba(239,68,68,0.15)"
		case "create":
			return "rgba(52,211,153,0.15)"
		case "update", "patch":
			return "rgba(251,191,36,0.15)"
		case "get":
			return "rgba(96,165,250,0.1)"
		case "list":
			return "rgba(148,163,184,0.1)"
		default:
			return "rgba(255,255,255,0.05)"
		}
	},
	"resultColor": func(result int) string {
		if result >= 500 {
			return "#f87171"
		}
		if result >= 400 {
			return "#fbbf24"
		}
		return "#34d399"
	},
	"maxVal": func(m map[string]int) int {
		max := 0
		for _, v := range m {
			if v > max {
				max = v
			}
		}
		return max
	},
	"barWidth": func(val, max int) int {
		if max == 0 {
			return 0
		}
		w := val * 100 / max
		if w < 1 {
			return 1
		}
		return w
	},
}).Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AuditRadar — Summary</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='15' fill='%23080810'/%3E%3Ccircle cx='16' cy='16' r='11' fill='none' stroke='%233b82f6' stroke-width='0.8' stroke-opacity='0.4'/%3E%3Ccircle cx='16' cy='16' r='7' fill='none' stroke='%233b82f6' stroke-width='0.8' stroke-opacity='0.65'/%3E%3Ccircle cx='16' cy='16' r='3' fill='none' stroke='%233b82f6' stroke-width='0.8'/%3E%3Cline x1='16' y1='1' x2='16' y2='31' stroke='%233b82f6' stroke-width='0.4' stroke-opacity='0.2'/%3E%3Cline x1='1' y1='16' x2='31' y2='16' stroke='%233b82f6' stroke-width='0.4' stroke-opacity='0.2'/%3E%3Cline x1='16' y1='16' x2='27' y2='5' stroke='%23ee0000' stroke-width='2' stroke-opacity='1'/%3E%3Cline x1='16' y1='16' x2='5' y2='27' stroke='%233b82f6' stroke-width='1.5' stroke-opacity='0.9'/%3E%3Ccircle cx='24' cy='9' r='2' fill='%23ee0000'/%3E%3Ccircle cx='8' cy='24' r='1.5' fill='%233b82f6'/%3E%3C/svg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Epilogue:wght@700;800;900&family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <style>
    :root{--bg:#080810;--bg2:#0f0f1a;--bg3:#161625;--border:rgba(255,255,255,0.07);--red:#ff3b3b;--red-dim:rgba(255,59,59,0.15);--green:#34d399;--yellow:#fbbf24;--blue:#3b82f6;--purple:#a78bfa;--text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;--mono:'JetBrains Mono',monospace;--sans:'Epilogue',sans-serif;}
    body.light{--bg:#f1f5f9;--bg2:#e8edf5;--bg3:#dde3ee;--border:rgba(0,0,0,0.08);--red:#cc0000;--red-dim:rgba(204,0,0,0.12);--green:#059669;--yellow:#d97706;--blue:#2563eb;--purple:#7c3aed;--text:#0f172a;--text2:#334155;--text3:#64748b;}
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:var(--mono);background:var(--bg);color:var(--text);font-size:13px;min-height:100vh;}
    body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(238,0,0,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(238,0,0,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}
    header{position:relative;z-index:10;background:rgba(10,10,15,0.95);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px;backdrop-filter:blur(10px);box-shadow:0 1px 0 rgba(238,0,0,0.2),0 4px 20px rgba(0,0,0,0.4);}
    body.light header{background:rgba(241,245,249,0.97);box-shadow:0 1px 0 rgba(204,0,0,0.15),0 4px 12px rgba(0,0,0,0.08);}
    body.light header h1 .sep{color:rgba(0,0,0,0.18);}
    .brand-wrap{display:flex;align-items:center;gap:14px;}
    header h1{font-family:var(--sans);font-size:22px;font-weight:900;letter-spacing:-0.04em;line-height:1;}
    header h1 .audit{color:var(--red);}header h1 .sep{color:rgba(255,255,255,0.15);margin:0 2px;}header h1 .radar{color:var(--blue);}
    .sub{font-size:9px;font-family:var(--mono);color:var(--text3);margin-top:5px;letter-spacing:2px;text-transform:uppercase;}
    .live-dot{width:6px;height:6px;background:var(--red);border-radius:50%;display:inline-block;animation:blink 1.4s infinite;margin-right:6px;vertical-align:middle;box-shadow:0 0 6px var(--red);}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:0.2}}
    .nav-btn{display:inline-block;padding:6px 16px;border:1px solid var(--text2);border-radius:5px;color:var(--text);text-decoration:none;font-size:11px;font-family:var(--mono);font-weight:500;letter-spacing:0.5px;transition:all 0.15s;background:transparent;}
    .nav-btn:hover{border-color:var(--blue);color:var(--blue);background:rgba(59,130,246,0.08);}
    .nav-btn.active{border-color:var(--red);color:var(--red);background:var(--red-dim);}
    .theme-btn{background:transparent;border:1px solid var(--text3);border-radius:5px;color:var(--text2);font-family:var(--mono);font-size:11px;padding:6px 12px;cursor:pointer;transition:all 0.15s;}
    .refresh-btn{background:transparent;border:1px solid var(--text3);color:var(--text2);padding:6px 16px;border-radius:5px;cursor:pointer;font-size:11px;font-family:var(--mono);white-space:nowrap;flex-shrink:0;transition:all 0.2s;}
    .page-content{position:relative;z-index:1;padding:28px;}
    .page-title{font-family:var(--sans);font-size:18px;font-weight:700;color:var(--text);margin-bottom:24px;display:flex;align-items:center;gap:10px;}
    .page-title span{color:var(--text2);font-size:12px;font-family:var(--mono);font-weight:400;}
    .stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px;}
    .stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px 22px;position:relative;overflow:hidden;transition:border-color 0.2s;}
    .stat-card:hover{border-color:rgba(255,255,255,0.12);}
    .stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
    .stat-card.red::before{background:var(--red);}.stat-card.green::before{background:var(--green);}.stat-card.blue::before{background:var(--blue);}.stat-card.yellow::before{background:var(--yellow);}.stat-card.purple::before{background:var(--purple);}.stat-card.gray::before{background:var(--text3);}
    .stat-label{font-size:9px;color:var(--text2);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;}
    .stat-value{font-family:var(--sans);font-size:36px;font-weight:900;color:var(--text);line-height:1;}
    .stat-value.red{color:#f87171;}.stat-value.green{color:var(--green);}.stat-value.blue{color:var(--blue);}.stat-value.yellow{color:var(--yellow);}
    .stat-sub{font-size:10px;color:var(--text3);margin-top:6px;}
    .section-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}
    .section-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-bottom:20px;}
    .panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;}
    .panel-header{padding:14px 18px;border-bottom:1px solid var(--border);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:var(--text2);display:flex;align-items:center;justify-content:space-between;}
    .panel-header a{color:var(--text3);font-size:10px;text-decoration:none;letter-spacing:0.5px;text-transform:none;font-weight:400;}
    .panel-header a:hover{color:var(--red);}
    .panel-body{padding:16px 18px;}
    .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
    .bar-row:last-child{margin-bottom:0;}
    .bar-label{font-size:11px;color:var(--text);min-width:0;flex:0 0 160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);}
    .bar-label.actor{color:var(--blue);font-weight:600;}.bar-label.ns{color:var(--text2);}
    .bar-track{flex:1;height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;}
    .bar-fill{height:100%;border-radius:3px;transition:width 0.4s ease;}
    .bar-count{font-size:10px;color:var(--text3);flex:0 0 50px;text-align:right;font-family:var(--mono);}
    .verb-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
    .verb-row:last-child{margin-bottom:0;}
    .verb-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:0.8px;font-family:var(--mono);flex:0 0 70px;text-align:center;}
    .verb-track{flex:1;height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;}
    .verb-fill{height:100%;border-radius:3px;}
    .verb-count{font-size:10px;color:var(--text3);flex:0 0 50px;text-align:right;font-family:var(--mono);}
    .verb-pct{font-size:10px;color:var(--text3);flex:0 0 36px;text-align:right;}
    .chart-wrap{display:flex;align-items:flex-end;gap:3px;height:80px;padding:0 2px;}
    .chart-col{flex:1;display:flex;flex-direction:column;justify-content:flex-end;gap:1px;cursor:pointer;position:relative;}
    .chart-col:hover .chart-tooltip{display:block;}
    .chart-seg{width:100%;border-radius:2px 2px 0 0;min-height:2px;transition:opacity 0.2s;}
    .chart-col:hover .chart-seg{opacity:0.8;}
    .chart-labels{display:flex;gap:3px;padding:6px 2px 0;}
    .chart-label{flex:1;font-size:8px;color:var(--text3);text-align:center;font-family:var(--mono);overflow:hidden;}
    .chart-legend{display:flex;gap:14px;margin-top:12px;}
    .chart-legend-item{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--text2);}
    .chart-legend-dot{width:8px;height:8px;border-radius:2px;flex-shrink:0;}
    .chart-tooltip{display:none;position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:6px 10px;font-size:10px;white-space:nowrap;z-index:100;pointer-events:none;color:var(--text);}
    .err-row{display:grid;grid-template-columns:120px 160px 70px 1fr 50px;gap:10px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,0.04);align-items:center;}
    .err-row:last-child{border-bottom:none;}
    .err-header{font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;padding-bottom:8px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:120px 160px 70px 1fr 50px;gap:10px;}
    .err-ts{font-size:10px;color:var(--text3);font-family:var(--mono);}
    .err-actor{font-size:11px;color:var(--blue);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .err-verb{display:inline-block;padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;font-family:var(--mono);}
    .err-resource{font-size:11px;color:var(--text2);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .err-code{font-size:11px;font-weight:700;text-align:right;}
    ::-webkit-scrollbar{width:6px;height:6px;}::-webkit-scrollbar-track{background:var(--bg);}::-webkit-scrollbar-thumb{background:var(--text3);border-radius:3px;}
    .risk-stat-card{background:var(--bg2);border:1px solid rgba(255,255,255,0.06);border-top:2px solid var(--accent);border-radius:4px;padding:12px 8px;text-align:center;transition:border-color 0.15s,background 0.15s;}
    .risk-stat-card:hover{background:var(--bg3);}
    .risk-stat-icon{font-size:18px;margin-bottom:6px;height:20px;display:flex;align-items:center;justify-content:center;}
    .risk-stat-num{font-family:var(--mono);font-size:24px;font-weight:700;line-height:1.1;}
    .risk-stat-label{font-size:9px;text-transform:uppercase;letter-spacing:0.1em;color:var(--text3);margin-top:4px;}
    .bottom-panels{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start;}
    @media(max-width:900px){.bottom-panels{grid-template-columns:1fr;}}
    body.light .nav-btn{border:2px solid #334155 !important;color:#0f172a !important;background:#e2e8f0 !important;font-weight:600 !important;}
    body.light .nav-btn.active{border:2px solid #cc0000 !important;color:#cc0000 !important;background:rgba(204,0,0,0.1) !important;}
    body.light .theme-btn{border:2px solid #334155 !important;color:#0f172a !important;background:#e2e8f0 !important;}
  </style>
</head>
<body>
<header>
  <a href="/ui" class="brand-wrap" style="text-decoration:none;">
    <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32' width="38" height="38" style="flex-shrink:0;filter:drop-shadow(0 0 10px rgba(100,130,255,0.4))">
      <circle cx='16' cy='16' r='15' fill='#080810'/>
      <circle cx='16' cy='16' r='11' fill='none' stroke='#3b82f6' stroke-width='0.8' stroke-opacity='0.45'/>
      <circle cx='16' cy='16' r='7'  fill='none' stroke='#3b82f6' stroke-width='0.8' stroke-opacity='0.75'/>
      <circle cx='16' cy='16' r='3'  fill='none' stroke='#aab4c8' stroke-width='0.8'/>
      <line x1='16' y1='1' x2='16' y2='31' stroke='#3b82f6' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='1'  y1='16' x2='31' y2='16' stroke='#3b82f6' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='16' y1='16' x2='27' y2='5'  stroke='#ee0000' stroke-width='2'   stroke-opacity='1' stroke-linecap='round'/>
      <line x1='16' y1='16' x2='5'  y2='27' stroke='#3b82f6' stroke-width='1.5' stroke-opacity='0.9' stroke-linecap='round'/>
      <circle cx='24' cy='9'  r='2.2' fill='#ee0000'/>
      <circle cx='8'  cy='24' r='1.8' fill='#3b82f6'/>
    </svg>
    <div>
      <h1><span class="audit">audit</span><span class="sep">·</span><span class="radar">radar</span></h1>
      <div class="sub"><span class="live-dot"></span>real-time audit explorer</div>
    </div>
  </a>
  <div style="display:flex;align-items:center;gap:12px;">
    <nav style="display:flex;gap:4px;">
      <a href="/ui"      class="nav-btn nav-active-check" data-page="ui">Events</a>
      <a href="/summary" class="nav-btn nav-active-check" data-page="summary">Summary</a>
      <a href="/settings" class="nav-btn nav-active-check" data-page="settings">Settings</a>
    </nav>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀ light</button>
    <button class="refresh-btn" disabled style="opacity:0.25;cursor:default;pointer-events:none;">⏸ live</button>
    {{if .Username}}
    <div style="display:flex;align-items:center;gap:8px;padding:4px 10px;border:1px solid rgba(255,255,255,0.1);border-radius:5px;font-size:10px;font-family:var(--mono);">
      <span style="color:var(--text3);">{{if eq .Role "admin"}}⬡{{else if eq .Role "editor"}}◈{{else}}◇{{end}}</span>
      <span style="color:var(--text2);">{{.Username}}</span>
      <span style="font-size:9px;padding:1px 6px;border-radius:2px;font-weight:700;letter-spacing:0.08em;
        {{if eq .Role "admin"}}background:rgba(255,59,59,0.15);color:#ff8080;border:1px solid rgba(255,59,59,0.3);
        {{else if eq .Role "editor"}}background:rgba(59,130,246,0.15);color:#93c5fd;border:1px solid rgba(59,130,246,0.3);
        {{else}}background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.3);{{end}}">{{.Role}}</span>
      <a href="/auth/logout" style="color:var(--text3);font-size:10px;font-family:var(--mono);text-decoration:none;padding:2px 6px;border-radius:3px;border:1px solid rgba(255,255,255,0.07);transition:all 0.15s;" onmouseover="this.style.color='#f87171'" onmouseout="this.style.color=''">exit</a>
    </div>
    {{end}}
  </div>
</header>
<script>
  (function() {
    var path = window.location.pathname;
    document.querySelectorAll('.nav-btn').forEach(function(a) {
      if (a.getAttribute('href') === path) a.classList.add('active');
    });
  })();
  function toggleTheme() {
    var body = document.body, btn = document.getElementById('themeBtn');
    if (body.classList.contains('light')) { body.classList.remove('light'); btn.textContent = '\u2600 light'; localStorage.setItem('theme','dark'); }
    else { body.classList.add('light'); btn.textContent = '\u25d1 dark'; localStorage.setItem('theme','light'); }
  }
  (function() {
    if (localStorage.getItem('theme') === 'light') { document.body.classList.add('light'); var btn = document.getElementById('themeBtn'); if (btn) btn.textContent = '\u25d1 dark'; }
  })();
</script>
<div class="page-content">
  <div class="page-title">Cluster Overview <span>last 24h activity + all-time totals</span></div>
  <div class="stat-grid">
    <div class="stat-card blue"><div class="stat-label">Total Events</div><div class="stat-value blue">{{.TotalEvents}}</div><div class="stat-sub">all time in database</div></div>
    <div class="stat-card green"><div class="stat-label">Human Actions</div><div class="stat-value green">{{.HumanEvents}}</div><div class="stat-sub">{{pct .HumanEvents .TotalEvents}}% of total</div></div>
    <div class="stat-card yellow"><div class="stat-label">Mutations</div><div class="stat-value yellow">{{.MutationEvents}}</div><div class="stat-sub">create / update / patch / delete</div></div>
    <div class="stat-card red"><div class="stat-label">Errors</div><div class="stat-value red">{{.ErrorEvents}}</div><div class="stat-sub">4xx / 5xx responses</div></div>
    <div class="stat-card purple"><div class="stat-label">Service Accounts</div><div class="stat-value">{{.ServiceAccountEvents}}</div><div class="stat-sub">{{pct .ServiceAccountEvents .TotalEvents}}% of total</div></div>
    <div class="stat-card gray"><div class="stat-label">System</div><div class="stat-value">{{.SystemEvents}}</div><div class="stat-sub">{{pct .SystemEvents .TotalEvents}}% of total</div></div>
  </div>
  {{if .HourlyActivity}}
  <div class="panel" style="margin-bottom:20px;">
    <div class="panel-header">Activity — Last 24 Hours</div>
    <div class="panel-body">
      {{$maxTotal := 0}}
      {{range .HourlyActivity}}{{if gt .Total $maxTotal}}{{$maxTotal = .Total}}{{end}}{{end}}
      <div class="chart-wrap">
        {{range .HourlyActivity}}
        <div class="chart-col">
          <div class="chart-tooltip">{{.Hour}} — {{.Total}} events<br>▲ {{.Creates}} create &nbsp;▼ {{.Deletes}} delete &nbsp;~ {{.Updates}} update</div>
          {{if gt .Deletes 0}}<div class="chart-seg" style="height:{{barWidth .Deletes $maxTotal}}%;background:#f87171;"></div>{{end}}
          {{if gt .Updates 0}}<div class="chart-seg" style="height:{{barWidth .Updates $maxTotal}}%;background:#fbbf24;"></div>{{end}}
          {{if gt .Creates 0}}<div class="chart-seg" style="height:{{barWidth .Creates $maxTotal}}%;background:#34d399;"></div>{{end}}
        </div>
        {{end}}
      </div>
      <div class="chart-labels">{{range .HourlyActivity}}<div class="chart-label">{{.Hour}}</div>{{end}}</div>
      <div class="chart-legend">
        <div class="chart-legend-item"><div class="chart-legend-dot" style="background:#34d399"></div>Create</div>
        <div class="chart-legend-item"><div class="chart-legend-dot" style="background:#fbbf24"></div>Update/Patch</div>
        <div class="chart-legend-item"><div class="chart-legend-dot" style="background:#f87171"></div>Delete</div>
      </div>
    </div>
  </div>
  {{end}}
  <div class="section-grid">
    <div class="panel">
      <div class="panel-header">Top Actors <a href="/ui?interestingOnly=true">view events →</a></div>
      <div class="panel-body">
        {{$maxA := maxVal .TopActors}}
        {{range $actor, $count := .TopActors}}
        <div class="bar-row"><div class="bar-label actor" title="{{$actor}}">{{$actor}}</div><div class="bar-track"><div class="bar-fill" style="width:{{barWidth $count $maxA}}%;background:var(--blue);"></div></div><div class="bar-count">{{$count}}</div></div>
        {{end}}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">Top Resources</div>
      <div class="panel-body">
        {{$maxR := maxVal .TopResources}}
        {{range $res, $count := .TopResources}}
        <div class="bar-row"><div class="bar-label" title="{{$res}}">{{$res}}</div><div class="bar-track"><div class="bar-fill" style="width:{{barWidth $count $maxR}}%;background:var(--purple);"></div></div><div class="bar-count">{{$count}}</div></div>
        {{end}}
      </div>
    </div>
  </div>
  <div class="section-grid-3">
    <div class="panel">
      <div class="panel-header">Verb Breakdown</div>
      <div class="panel-body">
        {{$maxV := maxVal .TopVerbs}}
        {{range $verb, $count := .TopVerbs}}
        <div class="verb-row">
          <span class="verb-badge" style="background:{{verbBg $verb}};color:{{verbColor $verb}};border:1px solid {{verbColor $verb}}33;">{{$verb}}</span>
          <div class="verb-track"><div class="verb-fill" style="width:{{barWidth $count $maxV}}%;background:{{verbColor $verb}};opacity:0.7;"></div></div>
          <div class="verb-pct">{{pct $count $maxV}}%</div>
          <div class="verb-count">{{$count}}</div>
        </div>
        {{end}}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">Top Namespaces</div>
      <div class="panel-body">
        {{$maxN := maxVal .TopNamespaces}}
        {{range $ns, $count := .TopNamespaces}}
        <div class="bar-row"><div class="bar-label ns" title="{{$ns}}">{{$ns}}</div><div class="bar-track"><div class="bar-fill" style="width:{{barWidth $count $maxN}}%;background:var(--yellow);opacity:0.7;"></div></div><div class="bar-count">{{$count}}</div></div>
        {{end}}
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">Sources</div>
      <div class="panel-body">
        {{$maxS := maxVal .TopSources}}
        {{range $src, $count := .TopSources}}
        <div class="bar-row"><div class="bar-label" title="{{$src}}">{{$src}}</div><div class="bar-track"><div class="bar-fill" style="width:{{barWidth $count $maxS}}%;background:var(--green);opacity:0.7;"></div></div><div class="bar-count">{{$count}}</div></div>
        {{end}}
      </div>
    </div>
  </div>
  <div class="bottom-panels">
    <div class="panel">
      <div class="panel-header">AI Risk Assessment <span style="font-size:9px;font-weight:700;letter-spacing:0.05em;background:linear-gradient(90deg,#0f62fe,#4589ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">POWERED BY IBM GRANITE 3.2</span></div>
      <div class="panel-body">
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;">
          <a href="/ui?riskScore=high&offset=0" style="text-decoration:none;"><div class="risk-stat-card" style="--accent:#ef4444;"><div class="risk-stat-icon"><span style="display:inline-block;width:12px;height:12px;border-radius:2px;background:#ef4444;box-shadow:0 0 6px #ef4444;"></span></div><div class="risk-stat-num" style="color:#ef4444;">{{.RiskHigh}}</div><div class="risk-stat-label">High</div></div></a>
          <a href="/ui?riskScore=medium&offset=0" style="text-decoration:none;"><div class="risk-stat-card" style="--accent:#f59e0b;"><div class="risk-stat-icon"><span style="display:inline-block;width:12px;height:12px;border-radius:2px;background:#f59e0b;box-shadow:0 0 6px #f59e0b;"></span></div><div class="risk-stat-num" style="color:#f59e0b;">{{.RiskMedium}}</div><div class="risk-stat-label">Medium</div></div></a>
          <a href="/ui?riskScore=low&offset=0" style="text-decoration:none;"><div class="risk-stat-card" style="--accent:#22c55e;"><div class="risk-stat-icon"><span style="display:inline-block;width:12px;height:12px;border-radius:2px;background:#22c55e;box-shadow:0 0 6px #22c55e;"></span></div><div class="risk-stat-num" style="color:#22c55e;">{{.RiskLow}}</div><div class="risk-stat-label">Low</div></div></a>
          <a href="/ui?riskScore=none&offset=0" style="text-decoration:none;"><div class="risk-stat-card" style="--accent:var(--text3);"><div class="risk-stat-icon"><span style="letter-spacing:2px;color:var(--text3);font-size:14px;">···</span></div><div class="risk-stat-num" style="color:var(--text2);">{{.RiskNotAnalyzed}}</div><div class="risk-stat-label">Pending</div></div></a>
        </div>
        {{if .TopRiskEvents}}
        <div class="err-header" style="grid-template-columns:90px 120px 60px 1fr 55px;"><span>Time</span><span>Actor</span><span>Verb</span><span>Resource</span><span>Risk</span></div>
        {{range .TopRiskEvents}}
        <div class="err-row" style="grid-template-columns:90px 120px 60px 1fr 55px;">
          <span class="err-ts">{{.Timestamp | fmtTime}}</span>
          <span class="err-actor" title="{{.Actor}}">{{.Actor}}</span>
          <span class="err-verb" style="background:{{verbBg .Verb}};color:{{verbColor .Verb}};">{{.Verb}}</span>
          <span class="err-resource" title="{{.ActionSummary}}">{{.Resource}}{{if .Name}}/{{.Name}}{{end}}</span>
          <span>{{if eq .RiskScore "high"}}<span style="color:#ef4444;font-weight:700;font-size:9px;">HIGH</span>{{else}}<span style="color:#f59e0b;font-size:9px;">MED</span>{{end}}</span>
        </div>
        {{end}}
        {{end}}
      </div>
    </div>
    {{if .RecentErrors}}
    <div class="panel">
      <div class="panel-header">Recent Errors (4xx / 5xx) <a href="/ui?result=403">view all →</a></div>
      <div class="panel-body">
        <div class="err-header"><span>Time</span><span>Actor</span><span>Verb</span><span>Resource</span><span>Code</span></div>
        {{range .RecentErrors}}
        <div class="err-row">
          <span class="err-ts">{{.Timestamp | fmtTime}}</span>
          <span class="err-actor" title="{{.Actor}}">{{.Actor}}</span>
          <span class="err-verb" style="background:{{verbBg .Verb}};color:{{verbColor .Verb}};">{{.Verb}}</span>
          <span class="err-resource" title="{{.Resource}}/{{.Name}}">{{.Resource}}{{if .Name}}/{{.Name}}{{end}}</span>
          <span class="err-code" style="color:{{resultColor .Result}}">{{.Result}}</span>
        </div>
        {{end}}
      </div>
    </div>
    {{else}}<div></div>{{end}}
  </div>
</div>
</body>
</html>
`))

// ─────────────────────────────────────────────────────────────────────────────
// Settings handler
// ─────────────────────────────────────────────────────────────────────────────

type alertConfig struct {
	SlackWebhook       string
	SMTPHost           string
	SMTPPort           string
	SMTPUser           string
	EmailFrom          string
	EmailTo            string
	AlertOnHigh        string
	AlertOnHumanDelete string
	PollInterval       string
}

const (
	k8sAPI    = "https://kubernetes.default.svc"
	cmName    = "audit-alerter-config"
	cmNS      = "audit-vision"
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func k8sToken() string {
	b, err := os.ReadFile(tokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func k8sClient() *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ca, err := os.ReadFile(caFile); err == nil {
		pool.AppendCertsFromPEM(ca)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func getConfigMap() (map[string]string, error) {
	u := fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", k8sAPI, cmNS, cmName)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "Bearer "+k8sToken())
	resp, err := k8sClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &cm); err != nil {
		return nil, fmt.Errorf("parse error: %v (body: %s)", err, string(body))
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	return cm.Data, nil
}

func patchConfigMap(data map[string]string) error {
	u := fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", k8sAPI, cmNS, cmName)
	payload := map[string]interface{}{"data": data}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("PATCH", u, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+k8sToken())
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := k8sClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert Rules — structs + API handlers
// ─────────────────────────────────────────────────────────────────────────────

type ruleConditions struct {
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Actor     string `json:"actor"`
	ActorType string `json:"actor_type"`
	Resource  string `json:"resource"`
	Risk      string `json:"risk"`
	ResultMin int    `json:"result_min"`
	ResultMax int    `json:"result_max"`
}

type alertRule struct {
	ID           int64          `json:"id"`
	Name         string         `json:"name"`
	Enabled      bool           `json:"enabled"`
	Conditions   ruleConditions `json:"conditions"`
	Destinations []string       `json:"destinations"`
	CreatedAt    string         `json:"created_at"`
}

func (s *uiServer) loadRules(ctx context.Context) ([]alertRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, enabled, conditions, destinations, created_at
		FROM alert_rules ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []alertRule
	for rows.Next() {
		var r alertRule
		var condJSON []byte
		var createdAt time.Time
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &condJSON, &r.Destinations, &createdAt); err != nil {
			continue
		}
		json.Unmarshal(condJSON, &r.Conditions)
		r.CreatedAt = createdAt.Format("2006-01-02 15:04")
		rules = append(rules, r)
	}
	return rules, nil
}

// rulesAPI handles GET /settings/rules (list) and POST /settings/rules (create)
func (s *uiServer) rulesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		rules, err := s.loadRules(ctx)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		if rules == nil {
			rules = []alertRule{}
		}
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var rule alertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, 400)
			return
		}
		if rule.Name == "" {
			http.Error(w, `{"error":"name required"}`, 400)
			return
		}
		if len(rule.Destinations) == 0 {
			rule.Destinations = []string{"email"}
		}
		condJSON, _ := json.Marshal(rule.Conditions)
		var id int64
		err := s.pool.QueryRow(ctx, `
			INSERT INTO alert_rules (name, enabled, conditions, destinations)
			VALUES ($1, $2, $3, $4) RETURNING id
		`, rule.Name, rule.Enabled, condJSON, rule.Destinations).Scan(&id)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		rule.ID = id
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rule)

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// rulesAPIItem handles PATCH /settings/rules/{id} (toggle) and DELETE /settings/rules/{id}
func (s *uiServer) rulesAPIItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	idStr := strings.TrimPrefix(r.URL.Path, "/settings/rules/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, 400)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, 400)
			return
		}
		if body.Enabled == nil {
			http.Error(w, `{"error":"enabled field required"}`, 400)
			return
		}
		_, err := s.pool.Exec(ctx, `UPDATE alert_rules SET enabled=$1 WHERE id=$2`, *body.Enabled, id)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "enabled": *body.Enabled})

	case http.MethodDelete:
		_, err := s.pool.Exec(ctx, `DELETE FROM alert_rules WHERE id=$1`, id)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"deleted": true})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Exclusion Rules API — GET/POST /settings/exclusions
// ─────────────────────────────────────────────────────────────────────────────

func (s *uiServer) exclusionsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		rules, err := s.db.GetExclusionRules(ctx)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var rule model.ExclusionRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, 400)
			return
		}
		if rule.Name == "" {
			http.Error(w, `{"error":"name required"}`, 400)
			return
		}
		rule.Enabled = true
		created, err := s.db.InsertExclusionRule(ctx, rule)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created)

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

// exclusionsAPIItem handles PATCH /settings/exclusions/{id} and DELETE /settings/exclusions/{id}
func (s *uiServer) exclusionsAPIItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	idStr := strings.TrimPrefix(r.URL.Path, "/settings/exclusions/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid id"}`, 400)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var rule model.ExclusionRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, 400)
			return
		}
		rule.ID = id
		if err := s.db.UpdateExclusionRule(ctx, rule); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "ok": true})

	case http.MethodDelete:
		if err := s.db.DeleteExclusionRule(ctx, id); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"deleted": true})

	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

func (s *uiServer) settings(w http.ResponseWriter, r *http.Request) {
	type PageData struct {
		Cfg      alertConfig
		Success  string
		Error    string
		Username string
		Role     string
	}
	pd := PageData{}
	sess := sessionFromContext(r.Context())
	pd.Username = sess.Username
	pd.Role = string(sess.Role)
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			data := map[string]string{
				"ALERT_SLACK_WEBHOOK":   r.FormValue("slack_webhook"),
				"ALERT_SMTP_HOST":       r.FormValue("smtp_host"),
				"ALERT_SMTP_PORT":       r.FormValue("smtp_port"),
				"ALERT_SMTP_USER":       r.FormValue("smtp_user"),
				"ALERT_EMAIL_FROM":      r.FormValue("email_from"),
				"ALERT_EMAIL_TO":        r.FormValue("email_to"),
				"ALERT_POLL_INTERVAL":   r.FormValue("poll_interval"),
			}
			if r.FormValue("alert_on_high") == "" {
				data["ALERT_ON_HIGH"] = "false"
			} else {
				data["ALERT_ON_HIGH"] = "true"
			}
			if r.FormValue("alert_on_human_delete") == "" {
				data["ALERT_ON_HUMAN_DELETE"] = "false"
			} else {
				data["ALERT_ON_HUMAN_DELETE"] = "true"
			}
			if pass := r.FormValue("smtp_pass"); pass != "" {
				data["ALERT_SMTP_PASS"] = pass
			}
			if err := patchConfigMap(data); err != nil {
				pd.Error = "Failed to save: " + err.Error()
				log.Printf("settings patch error: %v", err)
			} else {
				pd.Success = "Settings saved! alerter will apply changes within 60s."
			}
		}
	}
	if cm, err := getConfigMap(); err == nil {
		pd.Cfg = alertConfig{
			SlackWebhook:       cm["ALERT_SLACK_WEBHOOK"],
			SMTPHost:           cm["ALERT_SMTP_HOST"],
			SMTPPort:           cm["ALERT_SMTP_PORT"],
			SMTPUser:           cm["ALERT_SMTP_USER"],
			EmailFrom:          cm["ALERT_EMAIL_FROM"],
			EmailTo:            cm["ALERT_EMAIL_TO"],
			AlertOnHigh:        cm["ALERT_ON_HIGH"],
			AlertOnHumanDelete: cm["ALERT_ON_HUMAN_DELETE"],
			PollInterval:       cm["ALERT_POLL_INTERVAL"],
		}
	} else {
		pd.Error = "Cannot read ConfigMap: " + err.Error() + " (check RBAC permissions)"
	}
	if pd.Cfg.SMTPPort == "" { pd.Cfg.SMTPPort = "587" }
	if pd.Cfg.PollInterval == "" { pd.Cfg.PollInterval = "30s" }
	if pd.Cfg.AlertOnHigh == "" { pd.Cfg.AlertOnHigh = "true" }
	if pd.Cfg.AlertOnHumanDelete == "" { pd.Cfg.AlertOnHumanDelete = "true" }
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	settingsTmpl.Execute(w, pd)
}

var settingsTmpl = template.Must(template.New("settings").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>audit·radar — settings</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Epilogue:wght@400;700;900&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
  :root{--bg:#080810;--bg2:#0f0f1a;--bg3:#161625;--border:rgba(255,255,255,0.07);--red:#ff3b3b;--red-dim:rgba(255,59,59,0.15);--blue:#3b82f6;--green:#34d399;--yellow:#fbbf24;--purple:#a78bfa;--text:#e2e8f0;--text1:#e2e8f0;--text2:#94a3b8;--text3:#64748b;--mono:'JetBrains Mono',monospace;--sans:'Epilogue',sans-serif;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text1);font-family:var(--mono);font-size:13px;min-height:100vh;}
  body.light{--bg:#f1f5f9;--bg2:#e8edf5;--bg3:#dde3ee;--border:rgba(0,0,0,0.08);--red:#cc0000;--red-dim:rgba(204,0,0,0.12);--blue:#2563eb;--green:#059669;--yellow:#d97706;--text:#0f172a;--text1:#0f172a;--text2:#334155;--text3:#64748b;}
  header{position:relative;z-index:10;background:rgba(10,10,15,0.95);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px;backdrop-filter:blur(10px);box-shadow:0 1px 0 rgba(238,0,0,0.2),0 4px 20px rgba(0,0,0,0.4);}
  body.light header{background:rgba(241,245,249,0.97);box-shadow:0 1px 0 rgba(204,0,0,0.15),0 4px 12px rgba(0,0,0,0.08);}
  body.light header h1 .sep{color:rgba(0,0,0,0.18);}
  .brand-wrap{display:flex;align-items:center;gap:14px;}
  header h1{font-family:var(--sans);font-size:22px;font-weight:900;letter-spacing:-0.04em;line-height:1;}
  header h1 .audit{color:var(--red);}header h1 .sep{color:rgba(255,255,255,0.15);margin:0 2px;}header h1 .radar{color:var(--blue);}
  .sub{font-size:9px;font-family:var(--mono);color:var(--text3);margin-top:5px;letter-spacing:2px;text-transform:uppercase;}
  .live-dot{width:6px;height:6px;background:var(--red);border-radius:50%;display:inline-block;animation:blink 1.4s infinite;margin-right:6px;vertical-align:middle;box-shadow:0 0 6px var(--red);}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0.2}}
  .nav-btn{display:inline-block;padding:6px 16px;border:1px solid var(--text2);border-radius:5px;color:var(--text1);text-decoration:none;font-size:11px;font-family:var(--mono);font-weight:500;letter-spacing:0.5px;transition:all 0.15s;background:transparent;}
  .nav-btn:hover{border-color:var(--blue);color:var(--blue);background:rgba(59,130,246,0.08);}
  .nav-btn.active{border-color:var(--red);color:var(--red);background:rgba(238,0,0,0.15);font-weight:700;}
  .theme-btn{background:transparent;border:1px solid var(--text2);border-radius:5px;color:var(--text1);font-family:var(--mono);font-size:11px;padding:6px 12px;cursor:pointer;transition:all 0.15s;}
  .refresh-btn{background:transparent;border:1px solid var(--text3);color:var(--text2);padding:6px 16px;border-radius:5px;cursor:pointer;font-size:11px;font-family:var(--mono);white-space:nowrap;flex-shrink:0;transition:all 0.2s;}
  body.light .nav-btn{border:2px solid #334155 !important;color:#0f172a !important;background:#e2e8f0 !important;font-weight:600 !important;}
  body.light .nav-btn:hover{border-color:#2563eb !important;color:#2563eb !important;background:rgba(37,99,235,0.08) !important;}
  body.light .nav-btn.active{border:2px solid #cc0000 !important;color:#cc0000 !important;background:rgba(204,0,0,0.1) !important;font-weight:700 !important;}
  body.light .theme-btn{border:2px solid #334155 !important;color:#0f172a !important;background:#e2e8f0 !important;font-weight:600 !important;}
  body.light .refresh-btn{border:2px solid #334155 !important;color:#0f172a !important;background:#e2e8f0 !important;}
  .page{max-width:680px;margin:40px auto;padding:0 24px;}
  .page-title{font-family:var(--sans);font-size:20px;font-weight:900;margin-bottom:4px;}
  .page-sub{font-size:10px;color:var(--text3);margin-bottom:32px;letter-spacing:0.05em;text-transform:uppercase;}
  .section{margin-bottom:28px;}
  .section-title{font-size:9px;text-transform:uppercase;letter-spacing:0.12em;color:var(--text3);border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:8px;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
  .section-title .dot{width:6px;height:6px;border-radius:50%;background:var(--blue);flex-shrink:0;}
  .field{margin-bottom:14px;}
  .field label{display:block;font-size:9px;text-transform:uppercase;letter-spacing:0.1em;color:var(--text3);margin-bottom:5px;}
  .field input[type=text],.field input[type=password],.field input[type=email]{width:100%;background:var(--bg2);border:1px solid rgba(255,255,255,0.08);border-radius:3px;color:var(--text1);font-family:var(--mono);font-size:12px;padding:8px 12px;outline:none;transition:border-color 0.15s;}
  .field input:focus{border-color:var(--blue);}
  .field .hint{font-size:9px;color:var(--text3);margin-top:4px;}
  .field-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
  .toggle-row{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:var(--bg2);border:1px solid rgba(255,255,255,0.06);border-radius:3px;margin-bottom:8px;}
  .toggle-label{font-size:11px;color:var(--text1);}
  .toggle-sub{font-size:9px;color:var(--text3);margin-top:2px;}
  .toggle{position:relative;width:36px;height:20px;flex-shrink:0;}
  .toggle input{opacity:0;width:0;height:0;}
  .toggle-slider{position:absolute;inset:0;background:var(--bg3);border-radius:20px;cursor:pointer;transition:0.2s;border:1px solid rgba(255,255,255,0.1);}
  .toggle input:checked + .toggle-slider{background:var(--blue);}
  .toggle-slider:before{content:'';position:absolute;width:14px;height:14px;left:2px;top:2px;background:#fff;border-radius:50%;transition:0.2s;}
  .toggle input:checked + .toggle-slider:before{transform:translateX(16px);}
  .btn-save{background:var(--blue);color:#fff;border:none;padding:9px 24px;border-radius:3px;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:0.06em;cursor:pointer;text-transform:uppercase;transition:opacity 0.15s;}
  .btn-save:hover{opacity:0.85;}
  .msg-ok{background:rgba(34,197,94,0.1);border:1px solid #22c55e;color:#86efac;padding:10px 14px;border-radius:3px;margin-bottom:20px;font-size:11px;}
  .msg-err{background:rgba(239,68,68,0.1);border:1px solid #ef4444;color:#fca5a5;padding:10px 14px;border-radius:3px;margin-bottom:20px;font-size:11px;}
  body.light .field input[type=text],body.light .field input[type=password],body.light .field input[type=email]{background:#e8edf8;border-color:rgba(0,0,0,0.1);color:#0f172a;}
  body.light .toggle-row{background:#e8edf8;border-color:rgba(0,0,0,0.08);}
  body.light .toggle-slider{background:#c8d4e8;}

  /* Rule Builder */
  .rules-wrap{margin-top:32px;}
  .rule-builder{background:var(--bg2);border:1px solid rgba(255,255,255,0.07);border-radius:4px;padding:18px;margin-bottom:16px;}
  .rule-builder .rb-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:var(--text2);margin-bottom:14px;display:flex;align-items:center;gap:8px;}
  .rb-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;}
  .rb-field label{display:block;font-size:9px;text-transform:uppercase;letter-spacing:0.1em;color:var(--text3);margin-bottom:4px;}
  .rb-field input,.rb-field select{width:100%;background:var(--bg3);border:1px solid rgba(255,255,255,0.08);border-radius:3px;color:var(--text1);font-family:var(--mono);font-size:11px;padding:6px 10px;outline:none;transition:border-color 0.15s;}
  .rb-field input:focus,.rb-field select:focus{border-color:var(--blue);}
  .rb-field select option{background:var(--bg2);}
  .rb-dest{display:flex;gap:10px;align-items:center;margin-bottom:14px;}
  .rb-dest label{font-size:9px;text-transform:uppercase;letter-spacing:0.1em;color:var(--text3);}
  .rb-dest .dest-opts{display:flex;gap:8px;}
  .dest-opt{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text2);cursor:pointer;}
  .dest-opt input{width:auto;cursor:pointer;}
  .rb-actions{display:flex;justify-content:flex-end;gap:8px;}
  .btn-add-rule{background:var(--blue);color:#fff;border:none;padding:7px 18px;border-radius:3px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.06em;cursor:pointer;text-transform:uppercase;transition:opacity 0.15s;}
  .btn-add-rule:hover{opacity:0.85;}
  .btn-cancel-rule{background:transparent;color:var(--text3);border:1px solid rgba(255,255,255,0.1);padding:7px 14px;border-radius:3px;font-family:var(--mono);font-size:10px;cursor:pointer;text-transform:uppercase;}
  .btn-cancel-rule:hover{color:var(--text1);}
  .btn-new-rule{background:transparent;border:1px dashed rgba(100,130,255,0.4);color:var(--blue);padding:8px 16px;border-radius:3px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:0.06em;cursor:pointer;text-transform:uppercase;transition:all 0.15s;width:100%;}
  .btn-new-rule:hover{border-color:var(--blue);background:rgba(100,130,255,0.07);}
  .rules-list{display:flex;flex-direction:column;gap:8px;margin-bottom:12px;}
  .rule-item{background:var(--bg2);border:1px solid rgba(255,255,255,0.06);border-radius:4px;padding:12px 14px;display:flex;align-items:center;gap:12px;}
  .rule-item.disabled{opacity:0.45;}
  .rule-name{font-size:12px;font-weight:700;color:var(--text1);flex:1;min-width:0;}
  .rule-conds{font-size:10px;color:var(--text3);font-family:var(--mono);flex:2;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .rule-dests{display:flex;gap:4px;flex-shrink:0;}
  .dest-badge{font-size:9px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;padding:2px 7px;border-radius:2px;background:rgba(100,130,255,0.15);color:var(--blue);}
  .dest-badge.slack{background:rgba(74,21,75,0.3);color:#e879f9;}
  .rule-toggle{flex-shrink:0;}
  .btn-del-rule{background:transparent;border:none;color:var(--text3);cursor:pointer;font-size:14px;padding:2px 6px;border-radius:3px;transition:color 0.15s;flex-shrink:0;}
  .btn-del-rule:hover{color:#ef4444;}
  .rules-empty{text-align:center;padding:24px;color:var(--text3);font-size:11px;font-family:var(--mono);}
  body.light .rule-builder{background:#e8edf8;border-color:rgba(0,0,0,0.08);}
  body.light .rb-field input,body.light .rb-field select{background:#d4ddf0;border-color:rgba(0,0,0,0.1);color:#0f172a;}
  body.light .rule-item{background:#e8edf8;border-color:rgba(0,0,0,0.07);}
  body.light .rb-field select option{background:#e8edf8;color:#0f172a;}
</style>
</head>
<body>
<header>
  <a href="/ui" class="brand-wrap" style="text-decoration:none;">
    <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32' width="38" height="38" style="flex-shrink:0;filter:drop-shadow(0 0 10px rgba(100,130,255,0.4))">
      <circle cx='16' cy='16' r='15' fill='#080810'/>
      <circle cx='16' cy='16' r='11' fill='none' stroke='#3b82f6' stroke-width='0.8' stroke-opacity='0.45'/>
      <circle cx='16' cy='16' r='7'  fill='none' stroke='#3b82f6' stroke-width='0.8' stroke-opacity='0.75'/>
      <circle cx='16' cy='16' r='3'  fill='none' stroke='#aab4c8' stroke-width='0.8'/>
      <line x1='16' y1='1' x2='16' y2='31' stroke='#3b82f6' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='1'  y1='16' x2='31' y2='16' stroke='#3b82f6' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='16' y1='16' x2='27' y2='5'  stroke='#ee0000' stroke-width='2'   stroke-opacity='1' stroke-linecap='round'/>
      <line x1='16' y1='16' x2='5'  y2='27' stroke='#3b82f6' stroke-width='1.5' stroke-opacity='0.9' stroke-linecap='round'/>
      <circle cx='24' cy='9'  r='2.2' fill='#ee0000'/>
      <circle cx='8'  cy='24' r='1.8' fill='#3b82f6'/>
    </svg>
    <div>
      <h1><span class="audit">audit</span><span class="sep">·</span><span class="radar">radar</span></h1>
      <div class="sub"><span class="live-dot"></span>real-time audit explorer</div>
    </div>
  </a>
  <div style="display:flex;align-items:center;gap:12px;">
    <nav style="display:flex;gap:4px;">
      <a href="/ui"       class="nav-btn" id="nav-ui">Events</a>
      <a href="/summary"  class="nav-btn" id="nav-summary">Summary</a>
      <a href="/settings" class="nav-btn active">Settings</a>
    </nav>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀ light</button>
    <button class="refresh-btn" disabled style="opacity:0.25;cursor:default;pointer-events:none;">⏸ live</button>
    {{if .Username}}
    <div style="display:flex;align-items:center;gap:8px;padding:4px 10px;border:1px solid rgba(255,255,255,0.1);border-radius:5px;font-size:10px;font-family:var(--mono);">
      <span style="color:var(--text3);">{{if eq .Role "admin"}}⬡{{else if eq .Role "editor"}}◈{{else}}◇{{end}}</span>
      <span style="color:var(--text2);">{{.Username}}</span>
      <span style="font-size:9px;padding:1px 6px;border-radius:2px;font-weight:700;letter-spacing:0.08em;
        {{if eq .Role "admin"}}background:rgba(255,59,59,0.15);color:#ff8080;border:1px solid rgba(255,59,59,0.3);
        {{else if eq .Role "editor"}}background:rgba(59,130,246,0.15);color:#93c5fd;border:1px solid rgba(59,130,246,0.3);
        {{else}}background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.3);{{end}}">{{.Role}}</span>
      <a href="/auth/logout" style="color:var(--text3);font-size:10px;font-family:var(--mono);text-decoration:none;padding:2px 6px;border-radius:3px;border:1px solid rgba(255,255,255,0.07);transition:all 0.15s;" onmouseover="this.style.color='#f87171'" onmouseout="this.style.color=''">exit</a>
    </div>
    {{end}}
  </div>
</header>
<div class="page">
  <div class="page-title">Alert Settings</div>
  <div class="page-sub">Configure alerter · changes apply within 60s</div>
  {{if .Success}}<div class="msg-ok">✓ {{.Success}}</div>{{end}}
  {{if .Error}}<div class="msg-err">✗ {{.Error}}</div>{{end}}
  <form method="POST" action="/settings">
    <div class="section">
      <div class="section-title"><span class="dot" style="background:#4a154b;"></span> Slack</div>
      <div class="field">
        <label>Incoming Webhook URL</label>
        <input type="text" name="slack_webhook" value="{{.Cfg.SlackWebhook}}" placeholder="https://hooks.slack.com/services/T.../B.../...">
        <div class="hint">Slack → Apps → Incoming Webhooks → Add to Slack → select channel → copy URL</div>
      </div>
    </div>
    <div class="section">
      <div class="section-title"><span class="dot" style="background:#f59e0b;"></span> Email (SMTP)</div>
      <div class="field-row">
        <div class="field"><label>SMTP Host</label><input type="text" name="smtp_host" value="{{.Cfg.SMTPHost}}" placeholder="smtp.gmail.com"></div>
        <div class="field"><label>SMTP Port</label><input type="text" name="smtp_port" value="{{.Cfg.SMTPPort}}" placeholder="587"></div>
      </div>
      <div class="field-row">
        <div class="field"><label>SMTP User</label><input type="text" name="smtp_user" value="{{.Cfg.SMTPUser}}" placeholder="alerts@yourcompany.com"></div>
        <div class="field"><label>SMTP Password</label><input type="password" name="smtp_pass" value="" placeholder="leave blank to keep existing"><div class="hint">Stored in Kubernetes Secret</div></div>
      </div>
      <div class="field-row">
        <div class="field"><label>From address</label><input type="text" name="email_from" value="{{.Cfg.EmailFrom}}" placeholder="audit-radar@yourcompany.com"></div>
        <div class="field"><label>To (comma-separated)</label><input type="text" name="email_to" value="{{.Cfg.EmailTo}}" placeholder="security@co.com, ops@co.com"></div>
      </div>
    </div>
    <div class="section">
      <div class="section-title"><span class="dot" style="background:#ef4444;"></span> Alert Rules</div>
      <div class="toggle-row">
        <div><div class="toggle-label">HIGH risk events</div><div class="toggle-sub">Alert when IBM Granite scores an event as HIGH risk</div></div>
        <label class="toggle"><input type="checkbox" name="alert_on_high" {{if eq .Cfg.AlertOnHigh "true"}}checked{{end}}><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <div><div class="toggle-label">Human DELETE</div><div class="toggle-sub">Alert when a human actor performs a DELETE operation</div></div>
        <label class="toggle"><input type="checkbox" name="alert_on_human_delete" {{if eq .Cfg.AlertOnHumanDelete "true"}}checked{{end}}><span class="toggle-slider"></span></label>
      </div>
    </div>
    <div class="section">
      <div class="section-title"><span class="dot"></span> Timing</div>
      <div class="field" style="max-width:200px;">
        <label>Poll Interval</label>
        <input type="text" name="poll_interval" value="{{.Cfg.PollInterval}}" placeholder="30s">
        <div class="hint">How often alerter checks for new events (e.g. 30s, 1m, 5m)</div>
      </div>
    </div>
    <button type="submit" class="btn-save">Save Settings</button>
  </form>

  <!-- ── Rule Builder ────────────────────────────────────────────────── -->
  <div class="rules-wrap">
    <div class="section-title" style="margin-top:8px;margin-bottom:16px;">
      <span class="dot" style="background:var(--red)"></span>
      Alert Rules
      <span style="font-size:9px;color:var(--text3);margin-left:auto;font-weight:400;">Custom trigger conditions → email / slack</span>
    </div>

    <!-- Existing rules list -->
    <div class="rules-list" id="rulesList">
      <div class="rules-empty" id="rulesEmpty">Loading rules...</div>
    </div>

    <!-- New rule form (hidden by default) -->
    <div class="rule-builder" id="ruleForm" style="display:none;">
      <div class="rb-title">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M8 1v14M1 8h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        New Alert Rule
      </div>
      <div class="rb-grid">
        <div class="rb-field">
          <label>Rule Name</label>
          <input type="text" id="rb_name" placeholder="e.g. Production Deletions">
        </div>
        <div class="rb-field">
          <label>Namespace <span style="opacity:0.5">(empty = any)</span></label>
          <input type="text" id="rb_namespace" placeholder="production">
        </div>
        <div class="rb-field">
          <label>Verb <span style="opacity:0.5">(empty = any)</span></label>
          <select id="rb_verb">
            <option value="">any</option>
            <option value="create">create</option>
            <option value="update">update</option>
            <option value="patch">patch</option>
            <option value="delete">delete</option>
            <option value="deletecollection">deletecollection</option>
            <option value="get">get</option>
            <option value="list">list</option>
            <option value="watch">watch</option>
          </select>
        </div>
        <div class="rb-field">
          <label>Actor <span style="opacity:0.5">(empty = any)</span></label>
          <input type="text" id="rb_actor" placeholder="devops-user">
        </div>
        <div class="rb-field">
          <label>Actor Type</label>
          <select id="rb_actor_type">
            <option value="">any</option>
            <option value="human">human</option>
            <option value="serviceaccount">serviceaccount</option>
            <option value="system">system</option>
          </select>
        </div>
        <div class="rb-field">
          <label>Resource <span style="opacity:0.5">(empty = any)</span></label>
          <input type="text" id="rb_resource" placeholder="secrets">
        </div>
        <div class="rb-field">
          <label>Risk Score</label>
          <select id="rb_risk">
            <option value="">any</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
        </div>
        <div class="rb-field">
          <label>Result Code Min <span style="opacity:0.5">(0 = ignore)</span></label>
          <input type="text" id="rb_result_min" placeholder="400">
        </div>
        <div class="rb-field">
          <label>Result Code Max <span style="opacity:0.5">(0 = ignore)</span></label>
          <input type="text" id="rb_result_max" placeholder="599">
        </div>
      </div>
      <div class="rb-dest">
        <label>Send to:</label>
        <div class="dest-opts">
          <label class="dest-opt"><input type="checkbox" id="rb_dest_email" checked> Email</label>
          <label class="dest-opt"><input type="checkbox" id="rb_dest_slack"> Slack</label>
        </div>
      </div>
      <div class="rb-actions">
        <button class="btn-cancel-rule" onclick="hideRuleForm()">Cancel</button>
        <button class="btn-add-rule" onclick="saveRule()">Add Rule</button>
      </div>
    </div>

    <button class="btn-new-rule" id="btnNewRule" onclick="showRuleForm()">+ New Rule</button>
  </div>

  <!-- ── Exclusion Filters ──────────────────────────────────────────────── -->
  <div class="rules-wrap" style="margin-top:40px;">
    <div class="section-title" style="margin-bottom:16px;">
      <span class="dot" style="background:#f59e0b"></span>
      Exclusion Filters
      <span style="font-size:9px;color:var(--text3);margin-left:auto;font-weight:400;">Events matching these rules are dropped before storage — collector reload: 30s</span>
    </div>

    <div id="exclusionsList">
      <div style="color:var(--text3);font-size:11px;padding:12px 0;font-family:var(--mono);">Loading...</div>
    </div>

    <!-- New exclusion form (hidden by default) -->
    <div class="rule-builder" id="exclusionForm" style="display:none;">
      <div class="rb-title">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M2 8h12M8 2l6 6-6 6" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span style="color:#f59e0b;">New Exclusion Rule</span>
        <span style="font-size:9px;color:var(--text3);font-weight:400;margin-left:4px;">— all conditions must match (AND logic); empty = any</span>
      </div>
      <div class="rb-grid">
        <div class="rb-field">
          <label>Rule Name <span style="color:#ef4444;">*</span></label>
          <input type="text" id="ex_name" placeholder="e.g. Drop cert-manager noise">
        </div>
        <div class="rb-field">
          <label>Namespace</label>
          <input type="text" id="ex_namespace" placeholder="cert-manager">
        </div>
        <div class="rb-field">
          <label>Actor</label>
          <input type="text" id="ex_actor" placeholder="system:serviceaccount:kube-*">
        </div>
        <div class="rb-field">
          <label>Actor Type</label>
          <select id="ex_actor_type">
            <option value="">any</option>
            <option value="human">human</option>
            <option value="serviceaccount">serviceaccount</option>
            <option value="system">system</option>
          </select>
        </div>
        <div class="rb-field">
          <label>Verb <span style="opacity:0.5">(comma-separated ok)</span></label>
          <input type="text" id="ex_verb" placeholder="get,list,watch">
        </div>
        <div class="rb-field">
          <label>Resource</label>
          <input type="text" id="ex_resource" placeholder="leases">
        </div>
      </div>
      <div class="rb-field" style="margin-bottom:14px;">
        <label>Comment</label>
        <input type="text" id="ex_comment" placeholder="Why this is excluded (optional)">
      </div>
      <div class="rb-actions">
        <button class="btn-cancel-rule" onclick="hideExclusionForm()">Cancel</button>
        <button class="btn-add-rule" style="background:#f59e0b;" onclick="saveExclusion()">Add Exclusion</button>
      </div>
    </div>

    <button class="btn-new-rule" id="btnNewExclusion" onclick="showExclusionForm()" style="border-color:rgba(245,158,11,0.4);color:#f59e0b;">+ New Exclusion</button>
  </div>

</div>
<script>
  function toggleTheme() {
    var body = document.body, btn = document.getElementById('themeBtn');
    if (body.classList.contains('light')) { body.classList.remove('light'); btn.textContent = '☀ light'; localStorage.setItem('theme','dark'); }
    else { body.classList.add('light'); btn.textContent = '◑ dark'; localStorage.setItem('theme','light'); }
  }
  (function() {
    if (localStorage.getItem('theme') === 'light') { document.body.classList.add('light'); var btn = document.getElementById('themeBtn'); if (btn) btn.textContent = '◑ dark'; }
  })();

  // ── Rules API ────────────────────────────────────────────────────────────
  var rules = [];

  function loadRules() {
    fetch('/settings/rules').then(function(r){ return r.json(); }).then(function(data) {
      rules = data;
      renderRules();
    }).catch(function(e) {
      document.getElementById('rulesList').innerHTML = '<div style="color:#f87171;font-size:11px;">Failed to load rules: ' + e + '</div>';
    });
  }

  function renderRules() {
    var el = document.getElementById('rulesList');
    if (!rules || rules.length === 0) {
      el.innerHTML = '<div style="color:var(--text3);font-size:11px;padding:12px 0;font-family:var(--mono);">No custom rules yet. Click "+ New Rule" to create one.</div>';
      return;
    }
    var verbColor = {create:'#34d399',update:'#fbbf24',patch:'#fbbf24',delete:'#f87171'};
    var riskColor = {high:'#ef4444',medium:'#f59e0b',low:'#22c55e'};
    var html = '<div style="display:flex;flex-direction:column;gap:8px;">';
    rules.forEach(function(r) {
      var conds = [];
      var c = r.conditions || {};
      if (c.namespace) conds.push('<span style="color:var(--text3)">ns=</span><b>' + c.namespace + '</b>');
      if (c.verb) conds.push('<span style="color:var(--text3)">verb=</span><span style="color:' + (verbColor[c.verb]||'#94a3b8') + ';font-weight:700;">' + c.verb + '</span>');
      if (c.actor_type) conds.push('<span style="color:var(--text3)">type=</span><b>' + c.actor_type + '</b>');
      if (c.actor) conds.push('<span style="color:var(--text3)">actor=</span><b>' + c.actor + '</b>');
      if (c.resource) conds.push('<span style="color:var(--text3)">resource=</span><b>' + c.resource + '</b>');
      if (c.risk) conds.push('<span style="color:var(--text3)">risk=</span><span style="color:' + (riskColor[c.risk]||'#94a3b8') + ';font-weight:700;">' + c.risk + '</span>');
      if (c.result_min) conds.push('<span style="color:var(--text3)">result&ge;</span><b>' + c.result_min + '</b>');
      if (c.result_max) conds.push('<span style="color:var(--text3)">result&le;</span><b>' + c.result_max + '</b>');
      var dests = (r.destinations || ['email']);
      var enabledColor = r.enabled ? '#22c55e' : '#475569';
      html += '<div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid ' + enabledColor + ';border-radius:4px;padding:12px 14px;display:flex;align-items:center;gap:12px;">';
      html += '<div style="flex:1;min-width:0;">';
      html += '<div style="font-size:12px;font-weight:700;color:var(--text1);margin-bottom:6px;">' + r.name + '</div>';
      html += '<div style="font-size:11px;font-family:var(--mono);display:flex;flex-wrap:wrap;gap:6px;align-items:center;">';
      if (conds.length === 0) {
        html += '<span style="color:var(--text3)">all events</span>';
      } else {
        html += conds.join('<span style="color:var(--text3);opacity:0.5;margin:0 1px;">AND</span>');
      }
      html += '</div>';
      html += '<div style="margin-top:6px;font-size:10px;color:var(--text3);">→ ' + dests.join(' + ') + ' &nbsp;·&nbsp; created ' + r.created_at + '</div>';
      html += '</div>';
      html += '<div style="display:flex;gap:8px;flex-shrink:0;align-items:center;">';
      html += '<label style="display:flex;align-items:center;gap:5px;cursor:pointer;font-size:10px;color:var(--text3);font-family:var(--mono);">';
      html += '<input type="checkbox"' + (r.enabled ? ' checked' : '') + ' onchange="toggleRule(' + r.id + ', this.checked)" style="accent-color:var(--blue);width:13px;height:13px;cursor:pointer;">';
      html += (r.enabled ? 'on' : 'off');
      html += '</label>';
      html += '<button onclick="deleteRule(' + r.id + ')" style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);color:#f87171;padding:4px 10px;border-radius:3px;font-size:10px;font-family:var(--mono);cursor:pointer;transition:background 0.15s;" onmouseover="this.style.background=\'rgba(239,68,68,0.2)\'" onmouseout="this.style.background=\'rgba(239,68,68,0.08)\'">delete</button>';
      html += '</div>';
      html += '</div>';
    });
    html += '</div>';
    el.innerHTML = html;
  }

  function showRuleForm() {
    document.getElementById('ruleForm').style.display = 'block';
    document.getElementById('btnNewRule').style.display = 'none';
    document.getElementById('rb_name').focus();
  }

  function hideRuleForm() {
    document.getElementById('ruleForm').style.display = 'none';
    document.getElementById('btnNewRule').style.display = 'block';
  }

  function saveRule() {
    var name = document.getElementById('rb_name').value.trim();
    if (!name) { alert('Rule name is required'); return; }
    var destEmail = document.getElementById('rb_dest_email').checked;
    var destSlack = document.getElementById('rb_dest_slack').checked;
    if (!destEmail && !destSlack) { alert('Select at least one destination'); return; }
    var destinations = [];
    if (destEmail) destinations.push('email');
    if (destSlack) destinations.push('slack');
    var rule = {
      name: name,
      enabled: true,
      destinations: destinations,
      conditions: {
        namespace:  document.getElementById('rb_namespace').value.trim(),
        verb:       document.getElementById('rb_verb').value,
        actor:      document.getElementById('rb_actor').value.trim(),
        actor_type: document.getElementById('rb_actor_type').value,
        resource:   document.getElementById('rb_resource').value.trim(),
        risk:       document.getElementById('rb_risk').value,
        result_min: parseInt(document.getElementById('rb_result_min').value) || 0,
        result_max: parseInt(document.getElementById('rb_result_max').value) || 0
      }
    };
    fetch('/settings/rules', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(rule)
    }).then(function(r) {
      if (!r.ok) return r.json().then(function(e){ throw e.error || 'unknown error'; });
      return r.json();
    }).then(function() {
      hideRuleForm();
      // reset form
      ['rb_name','rb_namespace','rb_actor','rb_resource','rb_result_min','rb_result_max'].forEach(function(id){
        document.getElementById(id).value = '';
      });
      document.getElementById('rb_verb').value = '';
      document.getElementById('rb_actor_type').value = '';
      document.getElementById('rb_risk').value = '';
      document.getElementById('rb_dest_email').checked = true;
      document.getElementById('rb_dest_slack').checked = false;
      loadRules();
    }).catch(function(e) {
      alert('Error saving rule: ' + e);
    });
  }

  function toggleRule(id, enabled) {
    fetch('/settings/rules/' + id, {
      method: 'PATCH',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({enabled: enabled})
    }).then(function() { loadRules(); });
  }

  function deleteRule(id) {
    if (!confirm('Delete this rule?')) return;
    fetch('/settings/rules/' + id, {method:'DELETE'}).then(function() { loadRules(); });
  }

  loadRules();

  // ── Exclusion Rules ──────────────────────────────────────────────────────
  var exclusions = [];

  function loadExclusions() {
    fetch('/settings/exclusions').then(function(r){ return r.json(); }).then(function(data) {
      exclusions = data;
      renderExclusions();
    }).catch(function(e) {
      document.getElementById('exclusionsList').innerHTML = '<div style="color:#f87171;font-size:11px;">Failed to load: ' + e + '</div>';
    });
  }

  function renderExclusions() {
    var el = document.getElementById('exclusionsList');
    if (!exclusions || exclusions.length === 0) {
      el.innerHTML = '<div style="color:var(--text3);font-size:11px;padding:12px 0;font-family:var(--mono);">No exclusion rules. Events matching a rule will be dropped before storage.</div>';
      return;
    }
    var html = '<div style="display:flex;flex-direction:column;gap:8px;">';
    exclusions.forEach(function(r) {
      var tags = [];
      if (r.namespace) tags.push('ns=<b>' + r.namespace + '</b>');
      if (r.actorType) tags.push('type=<b>' + r.actorType + '</b>');
      if (r.actor)     tags.push('actor=<b>' + r.actor + '</b>');
      if (r.verb)      tags.push('verb=<b>' + r.verb + '</b>');
      if (r.resource)  tags.push('resource=<b>' + r.resource + '</b>');
      var enabledColor = r.enabled ? '#f59e0b' : '#475569';
      html += '<div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid ' + enabledColor + ';border-radius:4px;padding:12px 14px;display:flex;align-items:center;gap:12px;">';
      html += '<div style="flex:1;min-width:0;">';
      html += '<div style="font-size:12px;font-weight:700;color:var(--text1);margin-bottom:6px;">' + escH(r.name) + '</div>';
      html += '<div style="font-size:11px;font-family:var(--mono);display:flex;flex-wrap:wrap;gap:6px;align-items:center;color:var(--text2);">';
      if (tags.length === 0) { html += '<span style="color:var(--text3)">all events</span>'; }
      else { html += tags.join('<span style="color:var(--text3);opacity:0.5;margin:0 1px;">AND</span>'); }
      html += '</div>';
      if (r.comment) html += '<div style="margin-top:4px;font-size:10px;color:var(--text3);">' + escH(r.comment) + '</div>';
      html += '</div>';
      html += '<div style="display:flex;gap:8px;flex-shrink:0;align-items:center;">';
      html += '<label style="display:flex;align-items:center;gap:5px;cursor:pointer;font-size:10px;color:var(--text3);font-family:var(--mono);">';
      html += '<input type="checkbox"' + (r.enabled ? ' checked' : '') + ' onchange="toggleExclusion(' + r.id + ', this.checked, \'' + escH(r.name) + '\', \'' + escH(r.namespace||'') + '\', \'' + escH(r.actor||'') + '\', \'' + escH(r.actorType||'') + '\', \'' + escH(r.verb||'') + '\', \'' + escH(r.resource||'') + '\', \'' + escH(r.comment||'') + '\')" style="accent-color:#f59e0b;width:13px;height:13px;cursor:pointer;">';
      html += (r.enabled ? 'active' : 'off') + '</label>';
      html += '<button onclick="deleteExclusion(' + r.id + ')" style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);color:#f87171;padding:4px 10px;border-radius:3px;font-size:10px;font-family:var(--mono);cursor:pointer;" onmouseover="this.style.background=\'rgba(239,68,68,0.2)\'" onmouseout="this.style.background=\'rgba(239,68,68,0.08)\'">delete</button>';
      html += '</div></div>';
    });
    html += '</div>';
    el.innerHTML = html;
  }

  function escH(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function showExclusionForm() {
    document.getElementById('exclusionForm').style.display = 'block';
    document.getElementById('btnNewExclusion').style.display = 'none';
    document.getElementById('ex_name').focus();
  }

  function hideExclusionForm() {
    document.getElementById('exclusionForm').style.display = 'none';
    document.getElementById('btnNewExclusion').style.display = 'block';
  }

  function saveExclusion() {
    var name = document.getElementById('ex_name').value.trim();
    if (!name) { alert('Name is required'); return; }
    var rule = {
      name:      name,
      enabled:   true,
      namespace: document.getElementById('ex_namespace').value.trim(),
      actor:     document.getElementById('ex_actor').value.trim(),
      actorType: document.getElementById('ex_actor_type').value,
      verb:      document.getElementById('ex_verb').value.trim(),
      resource:  document.getElementById('ex_resource').value.trim(),
      comment:   document.getElementById('ex_comment').value.trim()
    };
    fetch('/settings/exclusions', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(rule)
    }).then(function(r) {
      if (!r.ok) return r.json().then(function(e){ throw e.error || 'error'; });
      return r.json();
    }).then(function() {
      hideExclusionForm();
      ['ex_name','ex_namespace','ex_actor','ex_verb','ex_resource','ex_comment'].forEach(function(id){
        document.getElementById(id).value = '';
      });
      document.getElementById('ex_actor_type').value = '';
      loadExclusions();
    }).catch(function(e) { alert('Error: ' + e); });
  }

  function toggleExclusion(id, enabled, name, namespace, actor, actorType, verb, resource, comment) {
    fetch('/settings/exclusions/' + id, {
      method: 'PATCH',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({id:id, name:name, enabled:enabled, namespace:namespace, actor:actor, actorType:actorType, verb:verb, resource:resource, comment:comment})
    }).then(function() { loadExclusions(); });
  }

  function deleteExclusion(id) {
    if (!confirm('Delete this exclusion rule? Events that were previously dropped will now be stored.')) return;
    fetch('/settings/exclusions/' + id, {method:'DELETE'}).then(function() { loadExclusions(); });
  }

  loadExclusions();
</script>
</body>
</html>
`))
