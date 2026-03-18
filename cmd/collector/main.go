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
    "os/exec"
    "strings"
    "sync"
    "time"

    "github.com/auditvision/internal/enrich"
    "github.com/auditvision/internal/model"
    "github.com/auditvision/internal/normalize"
    "github.com/auditvision/internal/store"
)

// ─────────────────────────────────────────────────────────────────────────────
// Exclusion rule cache — refreshed every 30s from DB
// ─────────────────────────────────────────────────────────────────────────────

var (
    exclusionMu    sync.RWMutex
    exclusionCache []model.ExclusionRule
)

func loadExclusionRules(ctx context.Context, db store.Store) {
    rules, err := db.GetExclusionRules(ctx)
    if err != nil {
	log.Printf("collector: load exclusion rules: %v", err)
	return
    }
    exclusionMu.Lock()
    exclusionCache = rules
    exclusionMu.Unlock()
    log.Printf("collector: loaded %d exclusion rules", len(rules))
}

func isExcluded(ne model.NormalizedEvent) bool {
    exclusionMu.RLock()
    rules := exclusionCache
    exclusionMu.RUnlock()
    for _, r := range rules {
	if store.ExclusionRuleMatch(r, ne.Namespace, ne.Actor, ne.ActorType, ne.Verb, ne.Resource) {
	    return true
	}
    }
    return false
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
    ctx := context.Background()

    dsn := mustEnv("DATABASE_URL")
    listenAddr := envOr("LISTEN_ADDR", ":8443")

    db, err := store.New(ctx, dsn)
    if err != nil {
	log.Fatalf("collector: connect to postgres: %v", err)
    }
    defer db.Close()

    enricher := enrich.New(db)

    // Prime snapshot cache
    primeSnapshots(ctx, db)
    go func() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
	    primeSnapshots(ctx, db)
	}
    }()

    // Load exclusion rules and refresh every 30s
    loadExclusionRules(ctx, db)
    go func() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
	    loadExclusionRules(ctx, db)
	}
    }()

    // Retention
    retentionDays := envOrInt("RETENTION_DAYS", 30)
    if retentionDays > 0 {
	retentionDur := time.Duration(retentionDays) * 24 * time.Hour
	log.Printf("collector: retention policy: %d days", retentionDays)
	go func() {
	    runPurge := func() {
		deleted, err := db.PurgeOldEvents(ctx, retentionDur)
		if err != nil {
		    log.Printf("collector: retention purge error: %v", err)
		    return
		}
		if deleted > 0 {
		    log.Printf("collector: retention purge: deleted %d events older than %d days", deleted, retentionDays)
		}
	    }
	    runPurge()
	    t := time.NewTicker(1 * time.Hour)
	    defer t.Stop()
	    for range t.C {
		runPurge()
	    }
	}()
    } else {
	log.Println("collector: retention policy: disabled (RETENTION_DAYS=0)")
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", healthzHandler)
    mux.HandleFunc("/audit-sink", auditSinkHandler(ctx, db, enricher))
    mux.HandleFunc("/vector-sink", vectorSinkHandler(ctx, db, enricher))
    mux.HandleFunc("/oauth-sink", oauthSinkHandler(ctx, db))

    vectorAddr := envOr("VECTOR_ADDR", ":8080")
    if vectorAddr != listenAddr {
	go func() {
	    log.Printf("collector: vector HTTP listener on %s", vectorAddr)
	    if err := http.ListenAndServe(vectorAddr, mux); err != nil {
		log.Fatalf("collector: vector listener: %v", err)
	    }
	}()
    } else {
	log.Printf("collector: vector-sink available on main listener %s", listenAddr)
    }

    log.Printf("collector: listening on %s", listenAddr)

    certFile := envOr("TLS_CERT_FILE", "")
    keyFile := envOr("TLS_KEY_FILE", "")
    if certFile != "" && keyFile != "" {
	log.Fatal(http.ListenAndServeTLS(listenAddr, certFile, keyFile, mux))
    } else {
	log.Println("collector: WARNING — running without TLS (dev mode)")
	log.Fatal(http.ListenAndServe(listenAddr, mux))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// /audit-sink
// ─────────────────────────────────────────────────────────────────────────────

func auditSinkHandler(ctx context.Context, db store.Store, enricher *enrich.Enricher) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
	    http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	    return
	}

	var list model.AuditEventList
	if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
	    log.Printf("collector: decode audit batch: %v", err)
	    http.Error(w, "bad request", http.StatusBadRequest)
	    return
	}

	log.Printf("collector: received batch of %d events", len(list.Items))

	for _, raw := range list.Items {
	    if raw.Stage != "ResponseComplete" {
		continue
	    }
	    ne := normalize.Event(raw)
	    enricher.Enrich(ctx, &ne, raw.RequestObject)
	    // Detect and store auth events before general filter
	    if ae, ok := extractAuthEvent(ne, raw.RequestObject); ok {
		if err := db.InsertAuthEvent(ctx, ae); err != nil {
		    log.Printf("collector: insert auth event %s: %v", raw.AuditID, err)
		}
	    }
	    if !shouldStore(ne) {
		continue
	    }
	    if err := db.InsertEvent(ctx, ne); err != nil {
		log.Printf("collector: insert event %s: %v", raw.AuditID, err)
		continue
	    }
	}
	w.WriteHeader(http.StatusOK)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// /vector-sink
// ─────────────────────────────────────────────────────────────────────────────

func vectorSinkHandler(ctx context.Context, db store.Store, enricher *enrich.Enricher) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
	    http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	    return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
	    http.Error(w, "read error", http.StatusBadRequest)
	    return
	}

	var events []model.VectorAuditEvent
	if err := json.Unmarshal(body, &events); err != nil {
	    dec := json.NewDecoder(bytes.NewReader(body))
	    for dec.More() {
		var single model.VectorAuditEvent
		if err2 := dec.Decode(&single); err2 != nil {
		    log.Printf("vector-sink: decode error: %v", err2)
		    http.Error(w, "bad request", http.StatusBadRequest)
		    return
		}
		events = append(events, single)
	    }
	}

	log.Printf("vector-sink: received batch of %d events", len(events))

	stored := 0
	for _, ve := range events {
	    raw := model.AuditEvent{
		AuditID:                  ve.AuditID,
		Level:                    ve.Level,
		Stage:                    ve.Stage,
		Verb:                     ve.Verb,
		RequestURI:               ve.RequestURI,
		RequestReceivedTimestamp: ve.RequestReceivedTimestamp,
		StageTimestamp:           ve.StageTimestamp,
		User:                     ve.User,
		SourceIPs:                ve.SourceIPs,
		UserAgent:                ve.UserAgent,
		ObjectRef:                ve.ObjectRef,
		ResponseStatus:           ve.ResponseStatus,
		Annotations:              ve.Annotations,
		RequestObject:            ve.RequestObject,
	    }
	    if raw.RequestReceivedTimestamp == "" {
		raw.RequestReceivedTimestamp = ve.Timestamp
	    }
	    if raw.Stage != "ResponseComplete" {
		continue
	    }
	    ne := normalize.Event(raw)
	    enricher.Enrich(ctx, &ne, raw.RequestObject)
	    // Detect and store auth events
	    if ae, ok := extractAuthEvent(ne, raw.RequestObject); ok {
		log.Printf("AUTH EVENT: type=%s actor=%s method=%s result=%d", ae.EventType, ae.Actor, ae.Method, ae.Result)
		if err := db.InsertAuthEvent(ctx, ae); err != nil {
		    log.Printf("vector-sink: insert auth event %s: %v", raw.AuditID, err)
		}
	    }
	    if !shouldStore(ne) {
		continue
	    }
	    if err := db.InsertEvent(ctx, ne); err != nil {
		log.Printf("vector-sink: insert event %s: %v", raw.AuditID, err)
		continue
	    }
	    stored++
	}
	log.Printf("vector-sink: stored %d/%d events", stored, len(events))
	w.WriteHeader(http.StatusOK)
    }
}

// /oauth-sink — receives infrastructure logs from openshift-authentication namespace
// Each entry is a container log line; message field contains oauth-server audit JSON
func oauthSinkHandler(ctx context.Context, db store.Store) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
	    http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	    return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
	    http.Error(w, "read error", http.StatusBadRequest)
	    return
	}

	// CLF sends array or newline-delimited JSON
	// Each entry: {"message": "<oauth audit json>", "kubernetes": {...}, ...}
	type infraLog struct {
	    Message   string `json:"message"`
	    Timestamp string `json:"timestamp"`
	    Kubernetes struct {
		NamespaceName string `json:"namespace_name"`
		ContainerName string `json:"container_name"`
	    } `json:"kubernetes"`
	}

	var entries []infraLog
	if err := json.Unmarshal(body, &entries); err != nil {
	    dec := json.NewDecoder(bytes.NewReader(body))
	    for dec.More() {
		var e infraLog
		if err2 := dec.Decode(&e); err2 != nil {
		    break
		}
		entries = append(entries, e)
	    }
	}

	log.Printf("oauth-sink: received %d entries", len(entries))
	if len(entries) > 0 {
	    // Debug: log first entry to understand format
	    log.Printf("oauth-sink: sample message=%q", entries[0].Message[:min(200, len(entries[0].Message))])
	}

	stored := 0
	for _, entry := range entries {
	    if entry.Message == "" {
		continue
	    }
	    // Fast pre-filter: oauth audit events are JSON containing this annotation key
	    if !strings.Contains(entry.Message, "authentication.openshift.io/decision") {
		continue
	    }
	    // Parse oauth audit JSON from message field
	    var oauthEvent struct {
		AuditID   string   `json:"auditID"`
		RequestURI string  `json:"requestURI"`
		Verb      string   `json:"verb"`
		SourceIPs []string `json:"sourceIPs"`
		UserAgent string   `json:"userAgent"`
		RequestReceivedTimestamp string `json:"requestReceivedTimestamp"`
		ResponseStatus struct {
		    Code int `json:"code"`
		} `json:"responseStatus"`
		Annotations map[string]string `json:"annotations"`
	    }
	    if err := json.Unmarshal([]byte(entry.Message), &oauthEvent); err != nil {
		continue
	    }
	    // Only process ResponseComplete stage (has annotations)
	    decision := oauthEvent.Annotations["authentication.openshift.io/decision"]
	    username := oauthEvent.Annotations["authentication.openshift.io/username"]
	    if decision == "" {
		continue
	    }
	    // Only /oauth/authorize events
	    if !strings.Contains(oauthEvent.RequestURI, "/oauth/authorize") {
		continue
	    }

	    sourceIP := ""
	    if len(oauthEvent.SourceIPs) > 0 {
		sourceIP = oauthEvent.SourceIPs[0]
	    }

	    success := decision == "allow"
	    eventType := "login"
	    if !success {
		eventType = "failed"
		if username == "" {
		    username = "unknown"
		}
	    }
	    if username == "" {
		continue
	    }

	    method := detectLoginMethod(oauthEvent.UserAgent, "oauth-server")
	    ae := model.AuthEvent{
		AuditID:   oauthEvent.AuditID,
		Timestamp: oauthEvent.RequestReceivedTimestamp,
		Actor:     username,
		Method:    method,
		SourceIP:  sourceIP,
		UserAgent: oauthEvent.UserAgent,
		Result:    oauthEvent.ResponseStatus.Code,
		Success:   success,
		EventType: eventType,
	    }
	    if err := db.InsertAuthEvent(ctx, ae); err != nil {
		log.Printf("oauth-sink: insert auth event: %v", err)
		continue
	    }
	    log.Printf("oauth-sink: AUTH EVENT type=%s actor=%s decision=%s ip=%s", eventType, username, decision, sourceIP)
	    stored++
	}
	log.Printf("oauth-sink: stored %d/%d", stored, len(entries))
	w.WriteHeader(http.StatusOK)
    }
}

func min(a, b int) int {
    if a < b {
	return a
    }
    return b
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"ok"}`))
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot priming
// ─────────────────────────────────────────────────────────────────────────────

func primeSnapshots(ctx context.Context, db store.Store) {
    var allSnaps []model.DeploymentSnapshot
    for _, kind := range []string{"deployments", "statefulsets", "daemonsets"} {
	out, err := exec.CommandContext(ctx, "oc", "get", kind, "-A", "-o", "json").Output()
	if err != nil {
	    log.Printf("collector: prime snapshots: oc get %s: %v", kind, err)
	    continue
	}
	var list model.OcDeploymentList
	if err := json.Unmarshal(out, &list); err != nil {
	    log.Printf("collector: prime snapshots: unmarshal %s: %v", kind, err)
	    continue
	}
	for _, dep := range list.Items {
	    replicas := int32(1)
	    if dep.Spec.Replicas != nil {
		replicas = *dep.Spec.Replicas
	    }
	    containers := map[string]string{}
	    envMap := map[string]string{}
	    resourcesMap := map[string]string{}
	    for _, c := range dep.Spec.Template.Spec.Containers {
		containers[c.Name] = c.Image
		for _, e := range c.Env {
		    envMap[c.Name+"/"+e.Name] = e.Value
		}
		for res, val := range c.Resources.Requests {
		    resourcesMap[c.Name+"/requests."+res] = val
		}
		for res, val := range c.Resources.Limits {
		    resourcesMap[c.Name+"/limits."+res] = val
		}
	    }
	    allSnaps = append(allSnaps, model.DeploymentSnapshot{
		Namespace:  dep.Metadata.Namespace,
		Name:       dep.Metadata.Name,
		Replicas:   replicas,
		Containers: containers,
		Env:        envMap,
		Resources:  resourcesMap,
	    })
	}
    }
    if len(allSnaps) == 0 {
	return
    }
    if err := db.BulkSetSnapshots(ctx, allSnaps); err != nil {
	log.Printf("collector: prime snapshots: bulk upsert: %v", err)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// shouldStore — built-in noise filter + exclusion rules
// ─────────────────────────────────────────────────────────────────────────────

func shouldStore(ne model.NormalizedEvent) bool {
    // User-defined exclusion rules checked first
    if isExcluded(ne) {
	return false
    }

    // Override — store everything (useful for debugging)
    if os.Getenv("STORE_ALL_VERBS") == "true" {
	return true
    }

    // Always store exec and portforward — security relevant
    if ne.Subresource == "exec" || ne.Subresource == "portforward" {
	return true
    }

    // Always store human actions
    if ne.ActorType == "human" {
	return true
    }

    // For service accounts and system actors — only store mutations
    switch ne.Verb {
    case "get", "list", "watch", "head":
	return false
    }

    // Skip noisy resources
    switch ne.Resource {
    case "leases", "subjectaccessreviews", "selfsubjectaccessreviews",
	"selfsubjectrulesreviews", "tokenreviews", "localsubjectaccessreviews",
	"selfsubjectreviews", "events":
	return false
    }

    // Skip system namespace SA/system mutations
    if ne.Namespace != "" && isSystemNamespace(ne.Namespace) {
	return false
    }

    // Skip cluster-scoped SA/system churn
    if ne.Namespace == "" && ne.ActorType != "human" {
	return false
    }

    return true
}

func isSystemNamespace(ns string) bool {
    if os.Getenv("SYSTEM_NS_FILTER") == "false" {
	return false
    }
    return strings.HasPrefix(ns, "openshift-") ||
	strings.HasPrefix(ns, "kube-") ||
	ns == "kube-system" ||
	ns == "kube-public" ||
	ns == "default"
}

// ─────────────────────────────────────────────────────────────────────────────
// extractAuthEvent — detects login/logout/token events from audit events
// Watches: oauthaccesstokens, oauthauthorizetokens, tokenrequests
// ─────────────────────────────────────────────────────────────────────────────

func extractAuthEvent(ne model.NormalizedEvent, requestObj *json.RawMessage) (model.AuthEvent, bool) {
    res := ne.Resource
    if res != "oauthaccesstokens" && res != "oauthauthorizetokens" && res != "tokenrequests" {
	return model.AuthEvent{}, false
    }

    isOAuthProxy := ne.Actor == "system:serviceaccount:openshift-authentication:oauth-openshift"
    if ne.ActorType == "system" {
	return model.AuthEvent{}, false
    }
    if ne.ActorType == "serviceaccount" && !isOAuthProxy {
	return model.AuthEvent{}, false
    }

    // Extract real username from requestObject
    actor := ne.Actor
    if isOAuthProxy {
	actor = "[login]"
	if requestObj != nil {
	    var obj struct {
		UserName string `json:"userName"`
		UserUID  string `json:"userUID"`
	    }
	    if err := json.Unmarshal(*requestObj, &obj); err == nil && obj.UserName != "" {
		actor = obj.UserName
	    }
	}
    }

    method := detectLoginMethod(ne.UserAgent, ne.Source)
    success := ne.Result >= 200 && ne.Result < 300

    eventType := "unknown"
    switch res {
    case "oauthaccesstokens":
	switch ne.Verb {
	case "create":
	    if isOAuthProxy {
		if success {
		    eventType = "login"
		} else {
		    eventType = "failed"
		}
	    } else {
		if success {
		    eventType = "token-issued"
		} else {
		    eventType = "failed"
		}
	    }
	case "delete":
	    eventType = "logout"
	}
    case "oauthauthorizetokens":
	switch ne.Verb {
	case "create":
	    // Skip — oauthaccesstokens create is the real login event
	    return model.AuthEvent{}, false
	case "delete":
	    return model.AuthEvent{}, false
	}
    case "tokenrequests":
	if ne.Verb == "create" {
	    if success {
		eventType = "token-issued"
	    } else {
		eventType = "failed"
	    }
	}
    }

    if eventType == "unknown" {
	return model.AuthEvent{}, false
    }

    // Skip if we couldn't resolve username for oauth proxy events
    if actor == "[login]" {
	return model.AuthEvent{}, false
    }

    if ne.ActorType == "human" {
	actor = ne.Actor
    }

    return model.AuthEvent{
	AuditID:   ne.AuditID,
	Timestamp: ne.Timestamp,
	Actor:     actor,
	Method:    method,
	SourceIP:  ne.SourceIP,
	UserAgent: ne.UserAgent,
	Result:    ne.Result,
	Success:   success,
	EventType: eventType,
    }, true
}


func detectLoginMethod(userAgent, source string) string {
    ua := strings.ToLower(userAgent)
    switch {
    case strings.Contains(ua, "oc/") || strings.Contains(ua, "openshift-client"):
	return "oc-cli"
    case strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "safari"):
	return "web-console"
    case strings.Contains(ua, "bridge/") || strings.Contains(ua, "openshift-console"):
	return "web-console"
    case strings.Contains(ua, "oauth-server"):
	return "web-console"
    case source == "console":
	return "web-console"
    case source == "cli":
	return "oc-cli"
    default:
	return "api-token"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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

func envOrInt(key string, def int) int {
    if v := os.Getenv(key); v != "" {
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
	    return n
	}
    }
    return def
}