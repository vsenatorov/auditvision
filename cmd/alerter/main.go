package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

type Config struct {
	DBURL string

	SlackWebhook string
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPass     string
	EmailFrom    string
	EmailTo      string

	AlertOnHigh        bool
	AlertOnHumanDelete bool

	PollInterval time.Duration
	UIBaseURL    string
}

func loadConfig() Config {
	return Config{
		DBURL:              mustEnv("DATABASE_URL"),
		SlackWebhook:       os.Getenv("ALERT_SLACK_WEBHOOK"),
		SMTPHost:           os.Getenv("ALERT_SMTP_HOST"),
		SMTPPort:           envOr("ALERT_SMTP_PORT", "587"),
		SMTPUser:           os.Getenv("ALERT_SMTP_USER"),
		SMTPPass:           os.Getenv("ALERT_SMTP_PASS"),
		EmailFrom:          os.Getenv("ALERT_EMAIL_FROM"),
		EmailTo:            os.Getenv("ALERT_EMAIL_TO"),
		UIBaseURL:          os.Getenv("ALERT_UI_BASE_URL"),
		AlertOnHigh:        envBool("ALERT_ON_HIGH", true),
		AlertOnHumanDelete: envBool("ALERT_ON_HUMAN_DELETE", true),
		PollInterval:       envDuration("ALERT_POLL_INTERVAL", 30*time.Second),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert event
// ─────────────────────────────────────────────────────────────────────────────

type AlertEvent struct {
	AuditID       string
	Timestamp     time.Time
	Actor         string
	ActorType     string
	Verb          string
	Resource      string
	Name          string
	Namespace     string
	Result        int
	ActionSummary string
	RiskScore     string
	RiskReason    string
	Reason        string
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom alert rules
// ─────────────────────────────────────────────────────────────────────────────

type RuleConditions struct {
	Namespace string `json:"namespace"`  // empty = any
	Verb      string `json:"verb"`       // empty = any
	Actor     string `json:"actor"`      // empty = any
	ActorType string `json:"actor_type"` // empty = any; human|serviceaccount|system
	Resource  string `json:"resource"`   // empty = any
	Risk      string `json:"risk"`       // empty = any; high|medium|low
	ResultMin int    `json:"result_min"` // 0 = ignore
	ResultMax int    `json:"result_max"` // 0 = ignore
}

type AlertRule struct {
	ID           int64
	Name         string
	Enabled      bool
	Conditions   RuleConditions
	Destinations []string // ["email", "slack"]
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()

	if cfg.SlackWebhook == "" && cfg.SMTPHost == "" {
		log.Printf("WARNING: No alert destinations configured — dry-run mode.")
	}

	log.Printf("alerter starting | poll=%s slack=%v email=%v high=%v humanDelete=%v",
		cfg.PollInterval,
		cfg.SlackWebhook != "",
		cfg.SMTPHost != "",
		cfg.AlertOnHigh,
		cfg.AlertOnHumanDelete,
	)

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	if err := migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	log.Printf("alerter ready — watching for events every %s", cfg.PollInterval)

	for range ticker.C {
		if err := poll(ctx, pool, cfg); err != nil {
			log.Printf("poll error: %v", err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DB migration
// ─────────────────────────────────────────────────────────────────────────────

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS alert_sent (
		    audit_id   TEXT NOT NULL,
		    reason     TEXT NOT NULL,
		    sent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    PRIMARY KEY (audit_id, reason)
		);

		CREATE TABLE IF NOT EXISTS alert_rules (
		    id           BIGSERIAL PRIMARY KEY,
		    name         TEXT NOT NULL,
		    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
		    conditions   JSONB NOT NULL DEFAULT '{}',
		    destinations TEXT[] NOT NULL DEFAULT '{email}',
		    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Poll loop
// ─────────────────────────────────────────────────────────────────────────────

func poll(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	// ── Built-in rules ────────────────────────────────────────────────────────
	if err := pollBuiltIn(ctx, pool, cfg); err != nil {
		log.Printf("builtin poll error: %v", err)
	}

	// ── Custom rules from DB ──────────────────────────────────────────────────
	rules, err := loadRules(ctx, pool)
	if err != nil {
		log.Printf("load rules error: %v", err)
		return err
	}
	for _, rule := range rules {
		if err := pollRule(ctx, pool, cfg, rule); err != nil {
			log.Printf("rule[%d] poll error: %v", rule.ID, err)
		}
	}
	return nil
}

// pollBuiltIn handles the legacy ALERT_ON_HIGH and ALERT_ON_HUMAN_DELETE rules.
func pollBuiltIn(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var events []AlertEvent

	if cfg.AlertOnHigh {
		rows, err := pool.Query(ctx, `
			SELECT e.audit_id, e.ts, e.actor, e.actor_type, e.verb,
			       e.resource, e.name, e.namespace, e.result,
			       e.action_summary, e.risk_score, COALESCE(e.risk_reason,'')
			FROM audit_events e
			LEFT JOIN alert_sent a ON a.audit_id = e.audit_id AND a.reason = 'risk=high'
			WHERE e.risk_score = 'high'
			  AND e.result != 404
			  AND a.audit_id IS NULL
			ORDER BY e.ts DESC LIMIT 50
		`)
		if err != nil {
			return fmt.Errorf("query high: %w", err)
		}
		for rows.Next() {
			var ev AlertEvent
			if err := rows.Scan(&ev.AuditID, &ev.Timestamp, &ev.Actor, &ev.ActorType,
				&ev.Verb, &ev.Resource, &ev.Name, &ev.Namespace, &ev.Result,
				&ev.ActionSummary, &ev.RiskScore, &ev.RiskReason); err != nil {
				continue
			}
			ev.Reason = "risk=high"
			events = append(events, ev)
		}
		rows.Close()
	}

	if cfg.AlertOnHumanDelete {
		rows, err := pool.Query(ctx, `
			SELECT e.audit_id, e.ts, e.actor, e.actor_type, e.verb,
			       e.resource, e.name, e.namespace, e.result,
			       e.action_summary, COALESCE(e.risk_score,''), COALESCE(e.risk_reason,'')
			FROM audit_events e
			LEFT JOIN alert_sent a ON a.audit_id = e.audit_id AND a.reason = 'human+delete'
			WHERE e.actor_type = 'human'
			  AND e.verb = 'delete'
			  AND e.result != 404
			  AND a.audit_id IS NULL
			ORDER BY e.ts DESC LIMIT 50
		`)
		if err != nil {
			return fmt.Errorf("query human+delete: %w", err)
		}
		for rows.Next() {
			var ev AlertEvent
			if err := rows.Scan(&ev.AuditID, &ev.Timestamp, &ev.Actor, &ev.ActorType,
				&ev.Verb, &ev.Resource, &ev.Name, &ev.Namespace, &ev.Result,
				&ev.ActionSummary, &ev.RiskScore, &ev.RiskReason); err != nil {
				continue
			}
			ev.Reason = "human+delete"
			events = append(events, ev)
		}
		rows.Close()
	}

	return sendAndMark(ctx, pool, cfg, events)
}

// loadRules fetches all enabled custom rules from the DB.
func loadRules(ctx context.Context, pool *pgxpool.Pool) ([]AlertRule, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, name, conditions, destinations
		FROM alert_rules
		WHERE enabled = TRUE
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []AlertRule
	for rows.Next() {
		var r AlertRule
		var condJSON []byte
		r.Enabled = true
		if err := rows.Scan(&r.ID, &r.Name, &condJSON, &r.Destinations); err != nil {
			continue
		}
		if err := json.Unmarshal(condJSON, &r.Conditions); err != nil {
			log.Printf("rule[%d] bad conditions JSON: %v", r.ID, err)
			continue
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// pollRule queries events matching a custom rule's conditions.
func pollRule(ctx context.Context, pool *pgxpool.Pool, cfg Config, rule AlertRule) error {
	reason := fmt.Sprintf("rule:%d", rule.ID)

	// Build dynamic WHERE clause
	conds := []string{
		"a.audit_id IS NULL",
		"e.result != 404",
	}
	args := []interface{}{reason}
	argN := 2 // $1 = reason used in JOIN

	c := rule.Conditions
	if c.Namespace != "" {
		conds = append(conds, fmt.Sprintf("e.namespace = $%d", argN))
		args = append(args, c.Namespace)
		argN++
	}
	if c.Verb != "" {
		conds = append(conds, fmt.Sprintf("e.verb = $%d", argN))
		args = append(args, c.Verb)
		argN++
	}
	if c.Actor != "" {
		conds = append(conds, fmt.Sprintf("e.actor = $%d", argN))
		args = append(args, c.Actor)
		argN++
	}
	if c.ActorType != "" {
		conds = append(conds, fmt.Sprintf("e.actor_type = $%d", argN))
		args = append(args, c.ActorType)
		argN++
	}
	if c.Resource != "" {
		conds = append(conds, fmt.Sprintf("e.resource = $%d", argN))
		args = append(args, c.Resource)
		argN++
	}
	if c.Risk != "" {
		conds = append(conds, fmt.Sprintf("e.risk_score = $%d", argN))
		args = append(args, c.Risk)
		argN++
	}
	if c.ResultMin > 0 {
		conds = append(conds, fmt.Sprintf("e.result >= $%d", argN))
		args = append(args, c.ResultMin)
		argN++
	}
	if c.ResultMax > 0 {
		conds = append(conds, fmt.Sprintf("e.result <= $%d", argN))
		args = append(args, c.ResultMax)
		argN++
	}

	query := fmt.Sprintf(`
		SELECT e.audit_id, e.ts, e.actor, e.actor_type, e.verb,
		       e.resource, e.name, e.namespace, e.result,
		       e.action_summary, COALESCE(e.risk_score,''), COALESCE(e.risk_reason,'')
		FROM audit_events e
		LEFT JOIN alert_sent a ON a.audit_id = e.audit_id AND a.reason = $1
		WHERE %s
		ORDER BY e.ts DESC LIMIT 50
	`, strings.Join(conds, " AND "))

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("query rule %d: %w", rule.ID, err)
	}

	var events []AlertEvent
	for rows.Next() {
		var ev AlertEvent
		if err := rows.Scan(&ev.AuditID, &ev.Timestamp, &ev.Actor, &ev.ActorType,
			&ev.Verb, &ev.Resource, &ev.Name, &ev.Namespace, &ev.Result,
			&ev.ActionSummary, &ev.RiskScore, &ev.RiskReason); err != nil {
			continue
		}
		ev.Reason = reason
		events = append(events, ev)
	}
	rows.Close()

	if len(events) == 0 {
		return nil
	}

	log.Printf("rule[%d] '%s': found %d new events", rule.ID, rule.Name, len(events))

	for _, ev := range events {
		for _, dest := range rule.Destinations {
			switch dest {
			case "slack":
				if cfg.SlackWebhook != "" {
					if err := sendSlack(cfg.SlackWebhook, ev, rule.Name); err != nil {
						log.Printf("slack error [%s]: %v", ev.AuditID, err)
					}
				}
			case "email":
				if cfg.SMTPHost != "" && cfg.EmailTo != "" {
					if err := sendEmail(cfg, ev, rule.Name); err != nil {
						log.Printf("email error [%s]: %v", ev.AuditID, err)
					}
				}
			}
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO alert_sent (audit_id, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			ev.AuditID, ev.Reason,
		); err != nil {
			log.Printf("mark sent error [%s]: %v", ev.AuditID, err)
		}
	}
	return nil
}

// sendAndMark sends alerts for built-in rules and marks them as sent.
func sendAndMark(ctx context.Context, pool *pgxpool.Pool, cfg Config, events []AlertEvent) error {
	if len(events) == 0 {
		return nil
	}
	log.Printf("found %d new alert events (built-in)", len(events))
	for _, ev := range events {
		if cfg.SlackWebhook != "" {
			if err := sendSlack(cfg.SlackWebhook, ev, ""); err != nil {
				log.Printf("slack error [%s]: %v", ev.AuditID, err)
			}
		}
		if cfg.SMTPHost != "" && cfg.EmailTo != "" {
			if err := sendEmail(cfg, ev, ""); err != nil {
				log.Printf("email error [%s]: %v", ev.AuditID, err)
			}
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO alert_sent (audit_id, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			ev.AuditID, ev.Reason,
		); err != nil {
			log.Printf("mark sent error [%s]: %v", ev.AuditID, err)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Slack
// ─────────────────────────────────────────────────────────────────────────────

func sendSlack(webhookURL string, ev AlertEvent, ruleName string) error {
	emoji := "🟡"
	color := "#f59e0b"
	title := "⚠ audit·radar Alert"

	switch ev.Reason {
	case "risk=high":
		emoji, color, title = "🔴", "#ef4444", "🚨 audit·radar — HIGH Risk Event"
	case "human+delete":
		emoji, color, title = "🗑", "#f97316", "⚠ audit·radar — Human DELETE Detected"
	default:
		if ruleName != "" {
			title = fmt.Sprintf("⚠ audit·radar — Rule: %s", ruleName)
		}
	}

	ts := ev.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	fields := []map[string]interface{}{
		{"title": "Actor", "value": fmt.Sprintf("`%s`", ev.Actor), "short": true},
		{"title": "Verb", "value": fmt.Sprintf("`%s`", strings.ToUpper(ev.Verb)), "short": true},
		{"title": "Resource", "value": fmt.Sprintf("`%s/%s`", ev.Resource, ev.Name), "short": true},
		{"title": "Namespace", "value": fmt.Sprintf("`%s`", ev.Namespace), "short": true},
		{"title": "Result", "value": fmt.Sprintf("`%d`", ev.Result), "short": true},
		{"title": "Time", "value": ts, "short": true},
	}
	if ev.RiskScore != "" {
		fields = append(fields, map[string]interface{}{
			"title": "Risk", "value": fmt.Sprintf("`%s`", strings.ToUpper(ev.RiskScore)), "short": true,
		})
	}
	if ev.RiskReason != "" {
		fields = append(fields, map[string]interface{}{
			"title": "AI Explanation", "value": ev.RiskReason, "short": false,
		})
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":       color,
				"title":       title,
				"text":        fmt.Sprintf("%s %s", emoji, ev.ActionSummary),
				"fields":      fields,
				"footer":      "audit·radar powered by IBM Granite 3.2",
				"footer_icon": "https://www.ibm.com/favicon.ico",
				"ts":          ev.Timestamp.Unix(),
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	log.Printf("slack alert sent [%s] reason=%s", ev.AuditID, ev.Reason)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Email
// ─────────────────────────────────────────────────────────────────────────────

func sendEmail(cfg Config, ev AlertEvent, ruleName string) error {
	triggerLabel := ev.Reason
	if ruleName != "" {
		triggerLabel = fmt.Sprintf("rule: %s", ruleName)
	}

	subject := fmt.Sprintf("[audit·radar] ⚠ %s — %s %s/%s",
		strings.ToUpper(triggerLabel), strings.ToUpper(ev.Verb), ev.Resource, ev.Name)

	ts := ev.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")

	var body strings.Builder
	body.WriteString("audit·radar Alert\n")
	body.WriteString(strings.Repeat("─", 50) + "\n\n")
	body.WriteString(fmt.Sprintf("Trigger:    %s\n", triggerLabel))
	body.WriteString(fmt.Sprintf("Time:       %s\n", ts))
	body.WriteString(fmt.Sprintf("Actor:      %s (%s)\n", ev.Actor, ev.ActorType))
	body.WriteString(fmt.Sprintf("Action:     %s\n", ev.ActionSummary))
	body.WriteString(fmt.Sprintf("Resource:   %s/%s\n", ev.Resource, ev.Name))
	body.WriteString(fmt.Sprintf("Namespace:  %s\n", ev.Namespace))
	body.WriteString(fmt.Sprintf("Result:     %d\n", ev.Result))
	if ev.RiskScore != "" {
		body.WriteString(fmt.Sprintf("Risk Score: %s\n", strings.ToUpper(ev.RiskScore)))
	}
	if ev.RiskReason != "" {
		body.WriteString(fmt.Sprintf("\nAI Explanation:\n%s\n", ev.RiskReason))
	}
	if cfg.UIBaseURL != "" {
		body.WriteString(fmt.Sprintf("\nView event: %s/events/%s\n",
			strings.TrimRight(cfg.UIBaseURL, "/"), ev.AuditID))
	}
	body.WriteString("\n" + strings.Repeat("─", 50) + "\n")
	body.WriteString("powered by audit·radar + IBM Granite 3.2\n")

	recipients := strings.Split(cfg.EmailTo, ",")
	for i := range recipients {
		recipients[i] = strings.TrimSpace(recipients[i])
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		cfg.EmailFrom, strings.Join(recipients, ", "), subject, body.String())

	addr := fmt.Sprintf("%s:%s", cfg.SMTPHost, cfg.SMTPPort)
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}
	if err := smtp.SendMail(addr, auth, cfg.EmailFrom, recipients, []byte(msg)); err != nil {
		return err
	}
	log.Printf("email alert sent [%s] to=%s reason=%s", ev.AuditID, cfg.EmailTo, ev.Reason)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env %s is not set", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
