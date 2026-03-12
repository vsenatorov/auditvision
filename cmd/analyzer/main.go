package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

type config struct {
    DatabaseURL string
    OllamaURL   string
    Model       string
    IntervalSec int
    BatchSize   int
}

func loadConfig() config {
    intervalSec := 30
    if v := os.Getenv("INTERVAL_SEC"); v != "" {
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
	    intervalSec = n
	}
    }
    batchSize := 5
    if v := os.Getenv("BATCH_SIZE"); v != "" {
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
	    batchSize = n
	}
    }
    return config{
	DatabaseURL: mustEnv("DATABASE_URL"),
	OllamaURL:   envOr("OLLAMA_URL", "http://ollama:11434"),
	Model:       envOr("OLLAMA_MODEL", "granite3.2:8b"),
	IntervalSec: intervalSec,
	BatchSize:   batchSize,
    }
}

func mustEnv(k string) string {
    v := os.Getenv(k)
    if v == "" {
	log.Fatalf("required env %s is not set", k)
    }
    return v
}

func envOr(k, def string) string {
    if v := os.Getenv(k); v != "" {
	return v
    }
    return def
}

// ─────────────────────────────────────────────────────────────────────────────
// DB helpers
// ─────────────────────────────────────────────────────────────────────────────

type auditRow struct {
    ID          int64
    AuditID     string
    Timestamp   time.Time
    Actor       string
    ActorType   string
    Verb        string
    Resource    string
    Subresource string
    Namespace   string
    Name        string
    Result      int
    Source      string
    ActionSummary string
    Changes     string // raw JSON
}

// migrate adds risk columns if not present — idempotent
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
    _, err := pool.Exec(ctx, `
	ALTER TABLE audit_events
	  ADD COLUMN IF NOT EXISTS risk_score  TEXT    NOT NULL DEFAULT '',
	  ADD COLUMN IF NOT EXISTS risk_reason TEXT    NOT NULL DEFAULT '',
	  ADD COLUMN IF NOT EXISTS analyzed_at TIMESTAMPTZ;

	CREATE INDEX IF NOT EXISTS idx_audit_events_risk
	  ON audit_events (risk_score)
	  WHERE risk_score != '';
    `)
    return err
}

// fetchUnanalyzed returns up to batchSize events that haven't been analyzed yet.
// We skip pure GET/LIST/WATCH on non-sensitive resources to save LLM calls.
func fetchUnanalyzed(ctx context.Context, pool *pgxpool.Pool, limit int) ([]auditRow, error) {
    rows, err := pool.Query(ctx, `
	SELECT
	  id, audit_id, ts, actor, actor_type, verb,
	  resource, subresource, namespace, name,
	  result, source, action_summary,
	  COALESCE(changes::text, '[]')
	FROM audit_events
	WHERE analyzed_at IS NULL
	  AND verb NOT IN ('get','list','watch')
	ORDER BY ts DESC
	LIMIT $1
    `, limit)
    if err != nil {
	return nil, err
    }
    defer rows.Close()

    var result []auditRow
    for rows.Next() {
	var r auditRow
	if err := rows.Scan(
	    &r.ID, &r.AuditID, &r.Timestamp, &r.Actor, &r.ActorType, &r.Verb,
	    &r.Resource, &r.Subresource, &r.Namespace, &r.Name,
	    &r.Result, &r.Source, &r.ActionSummary, &r.Changes,
	); err != nil {
	    return nil, err
	}
	result = append(result, r)
    }
    return result, rows.Err()
}

// saveResult writes risk assessment back to the DB.
func saveResult(ctx context.Context, pool *pgxpool.Pool, id int64, score, reason string) error {
    _, err := pool.Exec(ctx, `
	UPDATE audit_events
	   SET risk_score  = $1,
	       risk_reason = $2,
	       analyzed_at = NOW()
	 WHERE id = $3
    `, score, reason, id)
    return err
}

// markSkipped stamps analyzed_at without a score so we don't re-visit it.
func markSkipped(ctx context.Context, pool *pgxpool.Pool, id int64) error {
    _, err := pool.Exec(ctx, `
	UPDATE audit_events SET analyzed_at = NOW() WHERE id = $1
    `, id)
    return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Ollama client
// ─────────────────────────────────────────────────────────────────────────────

type ollamaRequest struct {
    Model  string `json:"model"`
    Prompt string `json:"prompt"`
    Stream bool   `json:"stream"`
    Options map[string]any `json:"options,omitempty"`
}

type ollamaResponse struct {
    Response string `json:"response"`
    Done     bool   `json:"done"`
}

type riskResult struct {
    Score  string // high | medium | low
    Reason string
}

func queryOllama(ctx context.Context, baseURL, model string, row auditRow) (riskResult, error) {
    prompt := buildPrompt(row)

    body, _ := json.Marshal(ollamaRequest{
	Model:  model,
	Prompt: prompt,
	Stream: false,
	Options: map[string]any{
	    "temperature": 0.1, // determinism is important for security scoring
	    "num_predict": 200,
	},
    })

    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
	baseURL+"/api/generate", bytes.NewReader(body))
    if err != nil {
	return riskResult{}, err
    }
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{Timeout: 60 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
	return riskResult{}, fmt.Errorf("ollama request: %w", err)
    }
    defer resp.Body.Close()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
	return riskResult{}, err
    }
    if resp.StatusCode != http.StatusOK {
	return riskResult{}, fmt.Errorf("ollama HTTP %d: %s", resp.StatusCode, respBody)
    }

    var ollamaResp ollamaResponse
    if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
	return riskResult{}, fmt.Errorf("parse ollama response: %w", err)
    }

    return parseRisk(ollamaResp.Response), nil
}

// buildPrompt constructs the security analysis prompt for Granite.
func buildPrompt(r auditRow) string {
    hour := r.Timestamp.UTC().Hour()
    timeCtx := "business hours (UTC)"
    if hour < 6 || hour > 22 {
	timeCtx = "outside business hours (UTC " + strconv.Itoa(hour) + ":xx)"
    }

    changesStr := ""
    if r.Changes != "[]" && r.Changes != "" {
	changesStr = "\nField changes: " + r.Changes
    }

    return fmt.Sprintf(`You are a Kubernetes/OpenShift security analyst. Analyze this audit event and assess its risk level.

Event details:
- Timestamp: %s (%s)
- Actor: %s (type: %s, source: %s)
- Action: %s on %s%s
- Namespace: %s
- Object name: %s
- HTTP result: %d
- Summary: %s%s

Respond in this EXACT format (no other text):
SCORE: <high|medium|low>
REASON: <one concise sentence explaining why>

Rules for scoring:
- high: delete/exec on sensitive resources (secrets, SA, RBAC, networkpolicy), anonymous access, mass operations, actions in production namespace by humans at unusual hours, failed auth (4xx on sensitive resources)
- medium: human making changes in production, creating/patching deployments with image changes, modifying configmaps/secrets, scale operations, changes outside business hours
- low: routine CI/CD service account operations, expected operator activity, non-sensitive resource mutations`,
	r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
	timeCtx,
	r.Actor, r.ActorType, r.Source,
	r.Verb, r.Resource,
	func() string {
	    if r.Subresource != "" {
		return "/" + r.Subresource
	    }
	    return ""
	}(),
	r.Namespace,
	r.Name,
	r.Result,
	r.ActionSummary,
	changesStr,
    )
}

// parseRisk extracts SCORE and REASON from Granite's response.
func parseRisk(raw string) riskResult {
    var score, reason string
    for _, line := range strings.Split(raw, "\n") {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "SCORE:") {
	    score = strings.TrimSpace(strings.TrimPrefix(line, "SCORE:"))
	    score = strings.ToLower(score)
	} else if strings.HasPrefix(line, "REASON:") {
	    reason = strings.TrimSpace(strings.TrimPrefix(line, "REASON:"))
	}
    }

    // Normalize score
    switch score {
    case "high", "medium", "low":
	// ok
    default:
	// fallback — try to infer from response text
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "high"):
	    score = "high"
	case strings.Contains(lower, "medium"):
	    score = "medium"
	default:
	    score = "low"
	}
    }

    if reason == "" {
	reason = strings.TrimSpace(raw)
	if len(reason) > 200 {
	    reason = reason[:200] + "..."
	}
    }

    return riskResult{Score: score, Reason: reason}
}

// isOllamaReady returns true if Ollama is up and the model is loaded.
func isOllamaReady(ctx context.Context, baseURL, model string) bool {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/tags", nil)
    if err != nil {
	return false
    }
    resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
    if err != nil {
	return false
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
	return false
    }
    var tags struct {
	Models []struct {
	    Name string `json:"name"`
	} `json:"models"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
	return false
    }
    for _, m := range tags.Models {
	if strings.HasPrefix(m.Name, strings.Split(model, ":")[0]) {
	    return true
	}
    }
    return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Main loop
// ─────────────────────────────────────────────────────────────────────────────

func main() {
    log.SetFlags(log.LstdFlags | log.Lmsgprefix)
    log.SetPrefix("analyzer: ")

    cfg := loadConfig()
    log.Printf("starting — ollama=%s model=%s interval=%ds batch=%d",
	cfg.OllamaURL, cfg.Model, cfg.IntervalSec, cfg.BatchSize)

    ctx := context.Background()

    // Connect to PostgreSQL
    pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
    if err != nil {
	log.Fatalf("connect to postgres: %v", err)
    }
    defer pool.Close()

    // Run migration
    if err := migrate(ctx, pool); err != nil {
	log.Fatalf("migrate: %v", err)
    }
    log.Println("DB migration OK — risk columns ready")

    // Wait for Ollama + model to be available
    log.Println("waiting for Ollama and model to be ready...")
    for {
	if isOllamaReady(ctx, cfg.OllamaURL, cfg.Model) {
	    log.Printf("Ollama ready, model %s loaded", cfg.Model)
	    break
	}
	log.Printf("Ollama not ready yet, retrying in 15s...")
	time.Sleep(15 * time.Second)
    }

    ticker := time.NewTicker(time.Duration(cfg.IntervalSec) * time.Second)
    defer ticker.Stop()

    // Run once immediately on startup, then on ticker
    runBatch(ctx, pool, cfg)
    for range ticker.C {
	runBatch(ctx, pool, cfg)
    }
}

func runBatch(ctx context.Context, pool *pgxpool.Pool, cfg config) {
    rows, err := fetchUnanalyzed(ctx, pool, cfg.BatchSize)
    if err != nil {
	log.Printf("fetchUnanalyzed error: %v", err)
	return
    }
    if len(rows) == 0 {
	return
    }

    log.Printf("analyzing batch of %d events", len(rows))

    for _, row := range rows {
	result, err := queryOllama(ctx, cfg.OllamaURL, cfg.Model, row)
	if err != nil {
	    log.Printf("ollama error for audit_id=%s: %v — will retry next cycle", row.AuditID, err)
	    // Do NOT mark as skipped — leave analyzed_at NULL so next poll retries
	    continue
	}

	if err := saveResult(ctx, pool, row.ID, result.Score, result.Reason); err != nil {
	    log.Printf("saveResult error for id=%d: %v", row.ID, err)
	    continue
	}

	log.Printf("audit_id=%s actor=%s verb=%s resource=%s → %s",
	    row.AuditID, row.Actor, row.Verb, row.Resource, result.Score)
    }
}