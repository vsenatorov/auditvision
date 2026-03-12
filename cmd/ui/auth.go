package main

// ─────────────────────────────────────────────────────────────────────────────
// OCP OAuth2 Authentication
//
// Flow:
//   1. User hits any protected page → middleware redirects to /auth/login
//   2. /auth/login  → builds OCP OAuth URL → redirects browser
//   3. OCP authenticates user → redirects to /auth/callback?code=...
//   4. /auth/callback → exchanges code for token → fetches user info + groups
//   5. Maps OCP groups to roles → stores session in DB → sets cookie
//   6. Redirects to original URL
//
// Roles:
//   audit-radar-admins  → admin  (settings + rules + all)
//   audit-radar-editors → editor (rules, no settings)
//   any OCP user        → viewer (read-only)
//   not authenticated   → 401
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

type authConfig struct {
	Enabled      bool
	OAuthURL     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AdminGroup   string
	EditorGroup  string
	SessionTTL   time.Duration
	BasicUser    string // AUTH_BASIC_USER — local fallback username
	BasicPass    string // AUTH_BASIC_PASS — local fallback password
	BasicRole    Role   // AUTH_BASIC_ROLE — role for basic auth user (default: admin)
}

func loadAuthConfig() authConfig {
	enabled := os.Getenv("AUTH_ENABLED") == "true" || os.Getenv("AUTH_ENABLED") == "1"
	basicRole := Role(envOr("AUTH_BASIC_ROLE", "admin"))
	ocpURL := envOr("AUTH_OCP_URL", "")
	if ocpURL == "" {
		ocpURL = detectOAuthURL()
	}
	return authConfig{
		Enabled:      enabled,
		OAuthURL:     ocpURL,
		ClientID:     envOr("AUTH_CLIENT_ID", "audit-radar"),
		ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH_REDIRECT_URL"),
		AdminGroup:   envOr("AUTH_ADMIN_GROUP", "audit-radar-admins"),
		EditorGroup:  envOr("AUTH_EDITOR_GROUP", "audit-radar-editors"),
		SessionTTL:   24 * time.Hour,
		BasicUser:    os.Getenv("AUTH_BASIC_USER"),
		BasicPass:    os.Getenv("AUTH_BASIC_PASS"),
		BasicRole:    basicRole,
	}
}

// detectOAuthURL queries the OCP well-known endpoint to find the OAuth server URL.
// Works automatically inside any OCP cluster pod without configuration.
// Uses the cluster CA bundle mounted at /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
var cachedOAuthURL string

func detectOAuthURL() string {
	if cachedOAuthURL != "" {
		return cachedOAuthURL
	}
	// Load cluster CA — always mounted in OCP pods
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		log.Printf("auth: detectOAuthURL: cannot read cluster CA: %v", err)
		return ""
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}
	resp, err := client.Get("https://kubernetes.default.svc/.well-known/oauth-authorization-server")
	if err != nil {
		log.Printf("auth: detectOAuthURL: %v", err)
		return ""
	}
	defer resp.Body.Close()
	var meta struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil || meta.Issuer == "" {
		log.Printf("auth: detectOAuthURL: failed to parse well-known: %v", err)
		return ""
	}
	log.Printf("auth: auto-detected OAuth URL: %s", meta.Issuer)
	cachedOAuthURL = meta.Issuer
	return cachedOAuthURL
}

// ─────────────────────────────────────────────────────────────────────────────
// Roles
// ─────────────────────────────────────────────────────────────────────────────

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

func (r Role) CanAdmin() bool  { return r == RoleAdmin }
func (r Role) CanEdit() bool   { return r == RoleAdmin || r == RoleEditor }
func (r Role) CanView() bool   { return true }

// ─────────────────────────────────────────────────────────────────────────────
// Session
// ─────────────────────────────────────────────────────────────────────────────

type Session struct {
	Token     string
	Username  string
	Role      Role
	ExpiresAt time.Time
}

const sessionCookie = "ar_session"

// sessionFromRequest extracts and validates the session from the request cookie.
func (s *uiServer) sessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	ctx := r.Context()
	row := s.pool.QueryRow(ctx, `
		SELECT username, role, expires_at
		FROM ar_sessions
		WHERE token = $1 AND expires_at > NOW()
	`, cookie.Value)
	var sess Session
	var role string
	if err := row.Scan(&sess.Username, &role, &sess.ExpiresAt); err != nil {
		return nil, false
	}
	sess.Token = cookie.Value
	sess.Role = Role(role)
	return &sess, true
}

// createSession inserts a new session into DB and sets the cookie.
func (s *uiServer) createSession(ctx context.Context, w http.ResponseWriter, username string, role Role, ttl time.Duration) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(ttl)
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO ar_sessions (token, username, role, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (token) DO NOTHING
	`, token, username, string(role), expiresAt); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	})
	return nil
}

// deleteSession removes session from DB and clears cookie.
func (s *uiServer) deleteSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.pool.Exec(ctx, `DELETE FROM ar_sessions WHERE token = $1`, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookie,
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────────────────────

type contextKey string
const ctxSession contextKey = "session"

// authMiddleware wraps a handler and requires a valid session.
// If auth is disabled (AUTH_ENABLED != true) — passes through with admin role.
func (s *uiServer) authMiddleware(next http.HandlerFunc, minRole Role) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := loadAuthConfig()

		// Auth disabled — pass through as admin
		if !cfg.Enabled {
			sess := &Session{Username: "admin", Role: RoleAdmin}
			ctx := context.WithValue(r.Context(), ctxSession, sess)
			next(w, r.WithContext(ctx))
			return
		}

		sess, ok := s.sessionFromRequest(r)
		if !ok {
			// Save original URL for redirect after login
			redirectURL := r.URL.RequestURI()
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(redirectURL), http.StatusFound)
			return
		}

		// Check minimum role
		switch minRole {
		case RoleAdmin:
			if !sess.Role.CanAdmin() {
				s.forbiddenPage(w, r, sess)
				return
			}
		case RoleEditor:
			if !sess.Role.CanEdit() {
				s.forbiddenPage(w, r, sess)
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxSession, sess)
		next(w, r.WithContext(ctx))
	}
}

// sessionFromContext extracts session from context (set by middleware).
func sessionFromContext(ctx context.Context) *Session {
	if sess, ok := ctx.Value(ctxSession).(*Session); ok {
		return sess
	}
	return &Session{Username: "admin", Role: RoleAdmin} // fallback when auth disabled
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth handlers
// ─────────────────────────────────────────────────────────────────────────────

// GET /auth/callback — OCP redirects here with code
func (s *uiServer) authCallback(w http.ResponseWriter, r *http.Request) {
	cfg := loadAuthConfig()
	ctx := r.Context()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	// Decode next URL from state
	nextBytes, err := base64.URLEncoding.DecodeString(state)
	nextURL := "/ui"
	if err == nil && len(nextBytes) > 0 {
		nextURL = string(nextBytes)
	}

	// Exchange code for token
	// Build redirect URL — use config or auto-detect from request host
	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		redirectURL = scheme + "://" + r.Host + "/auth/callback"
	}
	token, err := s.exchangeCode(cfg, code, redirectURL)
	if err != nil {
		log.Printf("auth: token exchange failed: %v", err)
		http.Redirect(w, r, "/auth/login?error=token_exchange", http.StatusFound)
		return
	}

	// Get user info
	username, groups, err := s.fetchUserInfo(cfg, token)
	if err != nil {
		log.Printf("auth: userinfo failed: %v", err)
		http.Redirect(w, r, "/auth/login?error=userinfo", http.StatusFound)
		return
	}

	// Map groups to role
	role := groupsToRole(cfg, groups)
	log.Printf("auth: login user=%s groups=%v role=%s", username, groups, role)

	// Create session
	if err := s.createSession(ctx, w, username, role, cfg.SessionTTL); err != nil {
		log.Printf("auth: create session failed: %v", err)
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, nextURL, http.StatusFound)
}

// GET /auth/logout
func (s *uiServer) authLogout(w http.ResponseWriter, r *http.Request) {
	s.deleteSession(r.Context(), w, r)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

// ─────────────────────────────────────────────────────────────────────────────
// OCP API helpers
// ─────────────────────────────────────────────────────────────────────────────

// exchangeCode exchanges the OAuth code for an access token.
func (s *uiServer) exchangeCode(cfg authConfig, code, redirectURL string) (string, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURL},
	}
	req, err := http.NewRequest("POST",
		strings.TrimRight(cfg.OAuthURL, "/")+"/oauth/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k8sClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

// fetchUserInfo calls OCP API server to get username + groups.
func (s *uiServer) fetchUserInfo(cfg authConfig, token string) (string, []string, error) {
	// User info lives on the main API server, not the OAuth server
	// Use in-cluster API server address
	k8sHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	k8sPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	apiBase := fmt.Sprintf("https://%s:%s", k8sHost, k8sPort)

	req, err := http.NewRequest("GET", apiBase+"/apis/user.openshift.io/v1/users/~", nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := k8sClient().Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, body)
	}

	var user struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", nil, err
	}

	username := user.Metadata.Name
	groups := user.Groups
	if len(groups) == 0 {
		groups = s.fetchGroupsForUser(cfg, token, username)
	}

	return username, groups, nil
}

// fetchGroupsForUser queries OCP Groups API to find which groups contain the user.
func (s *uiServer) fetchGroupsForUser(cfg authConfig, token, username string) []string {
	k8sHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	k8sPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	apiBase := fmt.Sprintf("https://%s:%s", k8sHost, k8sPort)

	req, err := http.NewRequest("GET", apiBase+"/apis/user.openshift.io/v1/groups", nil)
	if err != nil {
		return s.fetchGroupsViaSA(username)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := k8sClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Try via service account token instead (UI SA may have access)
		return s.fetchGroupsViaSA(username)
	}

	var groupList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Users []string `json:"users"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &groupList); err != nil {
		return nil
	}

	var groups []string
	for _, g := range groupList.Items {
		for _, u := range g.Users {
			if u == username {
				groups = append(groups, g.Metadata.Name)
				break
			}
		}
	}
	return groups
}

// fetchGroupsViaSA uses the UI pod's service account token to read groups.
func (s *uiServer) fetchGroupsViaSA(username string) []string {
	k8sHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	k8sPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if k8sHost == "" {
		return nil
	}
	apiBase := fmt.Sprintf("https://%s:%s", k8sHost, k8sPort)
	saToken := k8sToken()

	req, err := http.NewRequest("GET", apiBase+"/apis/user.openshift.io/v1/groups", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+saToken)

	resp, err := k8sClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("auth: fetchGroupsViaSA returned %d", resp.StatusCode)
		return nil
	}

	var groupList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Users []string `json:"users"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &groupList); err != nil {
		return nil
	}

	var groups []string
	for _, g := range groupList.Items {
		for _, u := range g.Users {
			if u == username {
				groups = append(groups, g.Metadata.Name)
				break
			}
		}
	}
	log.Printf("auth: groups for %s via SA: %v", username, groups)
	return groups
}

// groupsToRole maps OCP group membership to an app role.
func groupsToRole(cfg authConfig, groups []string) Role {
	for _, g := range groups {
		if g == cfg.AdminGroup {
			return RoleAdmin
		}
	}
	for _, g := range groups {
		if g == cfg.EditorGroup {
			return RoleEditor
		}
	}
	return RoleViewer
}

// ─────────────────────────────────────────────────────────────────────────────
// DB migration for sessions
// ─────────────────────────────────────────────────────────────────────────────

func (s *uiServer) migrateAuth(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS ar_sessions (
		    token      TEXT        PRIMARY KEY,
		    username   TEXT        NOT NULL,
		    role       TEXT        NOT NULL DEFAULT 'viewer',
		    expires_at TIMESTAMPTZ NOT NULL,
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_ar_sessions_expires ON ar_sessions (expires_at);
	`)
	return err
}

// cleanExpiredSessions removes expired sessions periodically.
func (s *uiServer) cleanExpiredSessions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tag, err := s.pool.Exec(ctx, `DELETE FROM ar_sessions WHERE expires_at < NOW()`)
			if err == nil && tag.RowsAffected() > 0 {
				log.Printf("auth: cleaned %d expired sessions", tag.RowsAffected())
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 403 Forbidden page
// ─────────────────────────────────────────────────────────────────────────────

func (s *uiServer) forbiddenPage(w http.ResponseWriter, r *http.Request, sess *Session) {
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>403 — audit·radar</title>
<style>
  body{background:#080c14;color:#e8edf8;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px;}
  .code{font-size:64px;font-weight:900;background:linear-gradient(135deg,#e5383b,#4f6ef7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
  .msg{color:#4a5878;font-size:12px;letter-spacing:0.1em;text-transform:uppercase;}
  .user{color:#8899bb;font-size:11px;}
  a{color:#4f6ef7;text-decoration:none;font-size:11px;}
</style></head><body>
  <div class="code">403</div>
  <div class="msg">Insufficient permissions</div>
  <div class="user">Signed in as <b>%s</b> · role: <b>%s</b></div>
  <a href="/ui">← Back to events</a> &nbsp;·&nbsp; <a href="/auth/logout">Sign out</a>
</body></html>`, sess.Username, string(sess.Role))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Login page + Basic auth handlers
// ─────────────────────────────────────────────────────────────────────────────

// GET /auth/login — show login page
func (s *uiServer) authLoginPage(w http.ResponseWriter, r *http.Request) {
	cfg := loadAuthConfig()
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/ui"
	}
	errMsg := ""
	switch r.URL.Query().Get("error") {
	case "token_exchange":
		errMsg = "OAuth token exchange failed. Please try again."
	case "userinfo":
		errMsg = "Failed to retrieve user info from OpenShift."
	case "bad_credentials":
		errMsg = "Invalid username or password."
	case "basic_disabled":
		errMsg = "Basic auth is not configured on this instance."
	}
	clusterHost := ""
	if cfg.OAuthURL != "" {
		// extract host from OAuthURL for display
		u, err := url.Parse(cfg.OAuthURL)
		if err == nil {
			clusterHost = u.Host
		}
	}
	hasOCP := cfg.OAuthURL != "" && cfg.ClientID != "" // RedirectURL auto-built from request host
	hasBasic := cfg.BasicUser != "" && cfg.BasicPass != ""

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginPageTmpl.Execute(w, map[string]interface{}{
		"Next":        next,
		"Error":       errMsg,
		"ClusterHost": clusterHost,
		"HasOCP":      hasOCP,
		"HasBasic":    hasBasic,
	})
}

// GET /auth/ocp — redirect to OCP OAuth (split from /auth/login)
func (s *uiServer) authOCP(w http.ResponseWriter, r *http.Request) {
	cfg := loadAuthConfig()
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/ui"
	}
	// Auto-build redirect URL from request host if not configured
	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			scheme = "http"
		}
		redirectURL = scheme + "://" + r.Host + "/auth/callback"
	}
	state := base64.URLEncoding.EncodeToString([]byte(next))
	authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=user:info&state=%s",
		strings.TrimRight(cfg.OAuthURL, "/"),
		url.QueryEscape(cfg.ClientID),
		url.QueryEscape(redirectURL),
		url.QueryEscape(state),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// POST /auth/basic — username/password login
func (s *uiServer) authBasic(w http.ResponseWriter, r *http.Request) {
	cfg := loadAuthConfig()
	if cfg.BasicUser == "" || cfg.BasicPass == "" {
		http.Redirect(w, r, "/auth/login?error=basic_disabled", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/auth/login?error=bad_credentials", http.StatusFound)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	next := r.FormValue("next")
	if next == "" {
		next = "/ui"
	}
	if username != cfg.BasicUser || password != cfg.BasicPass {
		http.Redirect(w, r, "/auth/login?error=bad_credentials&next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	// Create session
	token, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	ctx := r.Context()
	expiry := time.Now().Add(cfg.SessionTTL)
	_, err = s.pool.Exec(ctx,
		`INSERT INTO ar_sessions (token, username, role, expires_at) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (token) DO NOTHING`,
		token, username, string(cfg.BasicRole), expiry)
	if err != nil {
		log.Printf("auth: basic session insert error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}
	log.Printf("auth: basic login user=%s role=%s", username, cfg.BasicRole)
	http.SetCookie(w, &http.Cookie{
		Name:     "ar_session",
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusFound)
}

// loginPageTmpl is the login page HTML template
var loginPageTmpl = template.Must(template.New("login").Parse(loginPageHTML))

const loginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>audit·radar — sign in</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Epilogue:wght@400;700;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --red:   #e5383b;
    --blue:  #4f6ef7;
    --bg:    #080c14;
    --bg2:   #0d1220;
    --bg3:   #131929;
    --border: rgba(255,255,255,0.07);
    --text1: #e8edf8;
    --text2: #8899bb;
    --text3: #4a5878;
    --mono:  'JetBrains Mono', monospace;
    --head:  'Epilogue', sans-serif;
  }
  html { height: 100%; }
  body { min-height: 100%; background: var(--bg); color: var(--text1); font-family: var(--mono); margin: 0; }
  .radar-bg { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; pointer-events: none; z-index: 0; }
  .radar-ring { position: absolute; border-radius: 50%; border: 1px solid rgba(79,110,247,0.08); animation: pulse 4s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:0.6;transform:scale(1)} 50%{opacity:1;transform:scale(1.01)} }
  .radar-ring:nth-child(1){width:800px;height:800px;animation-delay:0s}
  .radar-ring:nth-child(2){width:580px;height:580px;animation-delay:0.6s}
  .radar-ring:nth-child(3){width:380px;height:380px;animation-delay:1.2s}
  .radar-ring:nth-child(4){width:200px;height:200px;animation-delay:1.8s}
  .radar-sweep { position: absolute; width: 400px; height: 400px; border-radius: 50%; animation: sweep 4s linear infinite; transform-origin: center; }
  @keyframes sweep { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
  .radar-sweep::after { content:''; position:absolute; inset:0; border-radius:50%; background: conic-gradient(from 0deg, transparent 300deg, rgba(229,56,59,0.08) 360deg); }
  .radar-dot { position:absolute; border-radius:50%; animation: dotpulse 4s ease-in-out infinite; }
  @keyframes dotpulse { 0%,100%{opacity:0;transform:scale(0.5)} 20%,80%{opacity:1;transform:scale(1)} }
  .page { position:relative; z-index:10; min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:32px; padding:24px; }
  .brand { display:flex; align-items:center; gap:14px; }
  .brand h1 { font-family:var(--head); font-size:28px; font-weight:900; letter-spacing:-0.04em; }
  .brand h1 .a { color:#e5383b; }
  .brand h1 .sep { color:rgba(255,255,255,0.15); margin:0 2px; }
  .brand h1 .r { color:#4f6ef7; }
  .brand-sub { font-size:9px; color:var(--text3); letter-spacing:2px; text-transform:uppercase; margin-top:4px; }
  .card { background:var(--bg2); border:1px solid var(--border); border-radius:12px; padding:28px 32px; width:100%; max-width:360px; display:flex; flex-direction:column; gap:16px; box-shadow:0 8px 40px rgba(0,0,0,0.5); animation: cardIn 0.4s ease; }
  @keyframes cardIn { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
  .card-title { font-size:11px; color:var(--text3); letter-spacing:2px; text-transform:uppercase; text-align:center; }
  .cluster-status { display:flex; align-items:center; gap:8px; font-size:10px; color:var(--text3); background:var(--bg3); border:1px solid var(--border); border-radius:6px; padding:7px 12px; }
  .status-dot { width:6px; height:6px; background:#22c55e; border-radius:50%; box-shadow:0 0 6px #22c55e; flex-shrink:0; animation: blink 2s infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
  .btn-ocp { width:100%; padding:12px 20px; background:transparent; border:1px solid rgba(229,56,59,0.4); border-radius:8px; color:var(--text1); font-family:var(--mono); font-size:12px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:10px; transition:all 0.2s; position:relative; overflow:hidden; }
  .btn-ocp::before { content:''; position:absolute; inset:0; background:rgba(229,56,59,0.06); opacity:0; transition:opacity 0.2s; }
  .btn-ocp:hover { border-color:rgba(229,56,59,0.8); box-shadow:0 0 16px rgba(229,56,59,0.2); transform:translateY(-1px); }
  .btn-ocp:hover::before { opacity:1; }
  .ocp-icon { width:18px; height:18px; flex-shrink:0; }
  .divider { text-align:center; font-size:10px; color:var(--text3); letter-spacing:1px; display:flex; align-items:center; gap:10px; }
  .divider::before,.divider::after { content:''; flex:1; height:1px; background:var(--border); }
  .field { display:flex; flex-direction:column; gap:6px; }
  .field label { font-size:10px; color:var(--text3); letter-spacing:1px; text-transform:uppercase; }
  .field input { background:var(--bg3); border:1px solid rgba(255,255,255,0.1); border-radius:6px; padding:10px 12px; color:var(--text1); font-family:var(--mono); font-size:12px; outline:none; transition:border-color 0.2s; }
  .field input:focus { border-color:var(--blue); }
  .field input::placeholder { color:var(--text3); }
  .btn-login { width:100%; padding:11px; background:linear-gradient(135deg,#4f6ef7,#3b5de8); border:none; border-radius:8px; color:#fff; font-family:var(--mono); font-size:12px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; cursor:pointer; transition:opacity 0.15s,transform 0.15s; }
  .btn-login:hover { opacity:0.88; transform:translateY(-1px); }
  .roles-hint { display:flex; align-items:center; gap:6px; justify-content:center; flex-wrap:wrap; font-size:10px; color:var(--text3); }
  .role-badge { font-size:9px; padding:2px 8px; border-radius:3px; font-weight:700; letter-spacing:0.08em; }
  .role-badge.viewer  { background:rgba(100,116,139,0.15); color:#94a3b8; border:1px solid rgba(100,116,139,0.3); }
  .role-badge.editor  { background:rgba(79,110,247,0.15);  color:#93c5fd; border:1px solid rgba(79,110,247,0.3); }
  .role-badge.admin   { background:rgba(229,56,59,0.15);   color:#fca5a5; border:1px solid rgba(229,56,59,0.3); }
  .error-msg { background:rgba(229,56,59,0.1); border:1px solid rgba(229,56,59,0.3); border-radius:6px; padding:8px 12px; font-size:11px; color:#fca5a5; text-align:center; }
  .footer { position:fixed; bottom:20px; font-size:10px; color:var(--text3); letter-spacing:1px; }
  .footer a { color:var(--text3); text-decoration:none; }
  .footer a:hover { color:var(--text2); }
</style>
</head>
<body>
<div class="radar-bg">
  <div class="radar-ring"></div>
  <div class="radar-ring"></div>
  <div class="radar-ring"></div>
  <div class="radar-ring"></div>
  <div class="radar-sweep"></div>
</div>
<div class="page">
  <div class="brand">
    <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32' width="44" height="44" style="filter:drop-shadow(0 0 12px rgba(100,130,255,0.4))">
      <circle cx='16' cy='16' r='15' fill='#080c14'/>
      <circle cx='16' cy='16' r='11' fill='none' stroke='#4f6ef7' stroke-width='0.8' stroke-opacity='0.45'/>
      <circle cx='16' cy='16' r='7'  fill='none' stroke='#4f6ef7' stroke-width='0.8' stroke-opacity='0.75'/>
      <circle cx='16' cy='16' r='3'  fill='none' stroke='#aab4c8' stroke-width='0.8'/>
      <line x1='16' y1='1' x2='16' y2='31' stroke='#4f6ef7' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='1'  y1='16' x2='31' y2='16' stroke='#4f6ef7' stroke-width='0.35' stroke-opacity='0.2'/>
      <line x1='16' y1='16' x2='27' y2='5'  stroke='#e5383b' stroke-width='2'   stroke-opacity='1' stroke-linecap='round'/>
      <line x1='16' y1='16' x2='5'  y2='27' stroke='#4f6ef7' stroke-width='1.5' stroke-opacity='0.9' stroke-linecap='round'/>
      <circle cx='24' cy='9'  r='2.2' fill='#e5383b'/>
      <circle cx='8'  cy='24' r='1.8' fill='#4f6ef7'/>
    </svg>
    <div>
      <h1><span class="a">audit</span><span class="sep">·</span><span class="r">radar</span></h1>
      <div class="brand-sub">real-time audit explorer</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Authenticate</div>
    {{if .ClusterHost}}
    <div class="cluster-status">
      <div class="status-dot"></div>
      <span>cluster: <b style="color:var(--text2)">{{.ClusterHost}}</b></span>
    </div>
    {{end}}
    {{if .Error}}
    <div class="error-msg">{{.Error}}</div>
    {{end}}
    {{if .HasOCP}}
    <a href="/auth/ocp?next={{.Next}}" class="btn-ocp">
      <svg class="ocp-icon" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="16" cy="16" r="15" fill="#e5383b" opacity="0.15" stroke="#e5383b" stroke-width="1"/>
        <path d="M10 20.5c0-3.3 2.7-6 6-6s6 2.7 6 6H10z" fill="#e5383b"/>
        <path d="M8 22h16" stroke="#e5383b" stroke-width="1.5" stroke-linecap="round"/>
        <circle cx="16" cy="11" r="3" fill="#e5383b" opacity="0.7"/>
      </svg>
      Sign in with OpenShift
    </a>
    {{end}}
    {{if and .HasOCP .HasBasic}}
    <div class="divider">or</div>
    {{end}}
    {{if .HasBasic}}
    <form method="POST" action="/auth/basic" style="display:contents">
      <input type="hidden" name="next" value="{{.Next}}">
      <div class="field">
        <label>Username</label>
        <input type="text" name="username" placeholder="admin" autocomplete="username" required>
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-login">Sign In</button>
    </form>
    {{end}}
    <div class="roles-hint">
      <span>Access levels:</span>
      <span class="role-badge viewer">viewer</span>
      <span class="role-badge editor">editor</span>
      <span class="role-badge admin">admin</span>
    </div>
  </div>
</div>
<div class="footer">
  audit·radar &nbsp;·&nbsp; <a href="https://audit-radar.com">audit-radar.com</a> &nbsp;·&nbsp; powered by IBM Granite 3.2
</div>
</body>
</html>`

// ─────────────────────────────────────────────────────────────────────────────
// OAuthClient auto-sync
// ─────────────────────────────────────────────────────────────────────────────

// syncOAuthRedirectURI patches the OAuthClient redirect URI to match the
// current cluster's Route hostname. Called once at startup.
// Requires the audit-ui ServiceAccount to have patch rights on oauthclients.
func syncOAuthRedirectURI(ctx context.Context) {
	cfg := loadAuthConfig()

	// If redirect URL is hardcoded — nothing to sync
	if cfg.RedirectURL != "" {
		return
	}

	// Read SA token and CA
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Printf("auth: syncOAuth: cannot read SA token: %v", err)
		return
	}
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		log.Printf("auth: syncOAuth: cannot read CA: %v", err)
		return
	}
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		log.Printf("auth: syncOAuth: cannot read namespace: %v", err)
		return
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	// Get Route hostname for audit-ui
	routeURL := fmt.Sprintf("https://kubernetes.default.svc/apis/route.openshift.io/v1/namespaces/%s/routes/audit-ui",
		strings.TrimSpace(string(ns)))
	req, _ := http.NewRequestWithContext(ctx, "GET", routeURL, nil)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("auth: syncOAuth: get route: %v", err)
		return
	}
	defer resp.Body.Close()

	var route struct {
		Spec struct {
			Host string `json:"host"`
			TLS  *struct{} `json:"tls"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&route); err != nil || route.Spec.Host == "" {
		log.Printf("auth: syncOAuth: cannot parse route: %v", err)
		return
	}

	redirectURI := "https://" + route.Spec.Host + "/auth/callback"
	log.Printf("auth: syncOAuth: detected redirect URI: %s", redirectURI)

	// Patch OAuthClient redirectURIs
	patch := fmt.Sprintf(`[{"op":"replace","path":"/redirectURIs","value":["%s"]}]`, redirectURI)
	patchURL := "https://kubernetes.default.svc/apis/oauth.openshift.io/v1/oauthclients/" + cfg.ClientID
	req2, _ := http.NewRequestWithContext(ctx, "PATCH", patchURL, strings.NewReader(patch))
	req2.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req2.Header.Set("Content-Type", "application/json-patch+json")

	resp2, err := client.Do(req2)
	if err != nil {
		log.Printf("auth: syncOAuth: patch oauthclient: %v", err)
		return
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == http.StatusOK {
		log.Printf("auth: syncOAuth: OAuthClient %s redirectURIs updated to [%s]", cfg.ClientID, redirectURI)
	} else {
		log.Printf("auth: syncOAuth: patch returned %d (need patch rights on oauthclients)", resp2.StatusCode)
	}
}
