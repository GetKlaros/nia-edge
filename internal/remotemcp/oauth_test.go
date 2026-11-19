package remotemcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// vendorAuth is a vendor's MCP server and its authorization server, on one
// HTTPS origin: the server at /mcp, the issuer at /as.
type vendorAuth struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex

	cimd, dcr, s256 bool
	resource        string

	registered  int
	challenges  map[string]string // code -> challenge
	clients     map[string]string // code -> client_id
	redirects   map[string]string // code -> redirect_uri
	accessValid map[string]bool
	refresh     string
	tokenForms  []url.Values
	mcpCalls    int
	authorized  url.Values
}

func newVendorAuth(t *testing.T) *vendorAuth {
	v := &vendorAuth{t: t, s256: true, dcr: true, challenges: map[string]string{}, clients: map[string]string{}, redirects: map[string]string{}, accessValid: map[string]bool{}, refresh: "refresh-1"}
	v.server = httptest.NewTLSServer(v)
	t.Cleanup(v.server.Close)
	v.resource = v.server.URL + "/mcp"
	return v
}

func (v *vendorAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	origin := v.server.URL
	switch r.URL.Path {
	case "/mcp":
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !v.accessValid[bearer] {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="repo:read"`, origin))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		v.mcpCalls++
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &msg)
		if len(msg.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result := map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}}
		if msg.Method == "tools/list" {
			result = map[string]any{"tools": []any{map[string]any{"name": "list_issues", "inputSchema": map[string]any{"type": "object"}}}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
	case "/.well-known/oauth-protected-resource/mcp":
		writeJSON(w, map[string]any{"resource": v.resource, "authorization_servers": []string{origin + "/as"}, "scopes_supported": []string{"repo:read", "repo:write"}})
	case "/.well-known/oauth-authorization-server/as":
		metadata := map[string]any{
			"issuer": origin + "/as", "authorization_endpoint": origin + "/as/authorize", "token_endpoint": origin + "/as/token",
		}
		if v.s256 {
			metadata["code_challenge_methods_supported"] = []string{"S256"}
		}
		if v.dcr {
			metadata["registration_endpoint"] = origin + "/as/register"
		}
		if v.cimd {
			metadata["client_id_metadata_document_supported"] = true
		}
		writeJSON(w, metadata)
	case "/as/register":
		v.registered++
		var body struct {
			RedirectURIs []string `json:"redirect_uris"`
			Method       string   `json:"token_endpoint_auth_method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.RedirectURIs) != 1 || !strings.HasPrefix(body.RedirectURIs[0], "http://127.0.0.1:") || body.Method != "none" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"client_id": "registered-client"})
	case "/as/authorize":
		query := r.URL.Query()
		v.authorized = query
		code := fmt.Sprintf("code-%d", len(v.challenges)+1)
		v.challenges[code] = query.Get("code_challenge")
		v.clients[code] = query.Get("client_id")
		v.redirects[code] = query.Get("redirect_uri")
		target, _ := url.Parse(query.Get("redirect_uri"))
		target.RawQuery = url.Values{"code": {code}, "state": {query.Get("state")}}.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	case "/as/token":
		_ = r.ParseForm()
		v.tokenForms = append(v.tokenForms, r.PostForm)
		form := r.PostForm
		if form.Get("resource") != v.resource {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "invalid_target"})
			return
		}
		switch form.Get("grant_type") {
		case "authorization_code":
			code := form.Get("code")
			sum := sha256.Sum256([]byte(form.Get("code_verifier")))
			if v.challenges[code] == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != v.challenges[code] || form.Get("client_id") != v.clients[code] || form.Get("redirect_uri") != v.redirects[code] {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"error": "invalid_grant"})
				return
			}
			delete(v.challenges, code)
			v.accessValid["access-1"] = true
			writeJSON(w, map[string]any{"access_token": "access-1", "token_type": "Bearer", "refresh_token": v.refresh, "expires_in": 3600})
		case "refresh_token":
			if form.Get("refresh_token") != v.refresh {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"error": "invalid_grant"})
				return
			}
			access := fmt.Sprintf("access-%d", len(v.accessValid)+1)
			v.accessValid[access] = true
			v.refresh = "refresh-" + access
			writeJSON(w, map[string]any{"access_token": access, "token_type": "bearer", "refresh_token": v.refresh, "expires_in": 3600})
		}
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (v *vendorAuth) http() *http.Client {
	client := v.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// browser opens the printed link, and follows it back to nia-edge, or
// returns where it was sent.
func (v *vendorAuth) browser(t *testing.T, said *io.PipeReader, follow bool) chan string {
	sent := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(said)
		opened := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if opened || !strings.HasPrefix(line, "https://") {
				continue
			}
			opened = true
			go func() {
				response, err := v.http().Get(line)
				if err != nil {
					t.Error(err)
					return
				}
				response.Body.Close()
				location := response.Header.Get("Location")
				if follow {
					if back, err := http.Get(location); err == nil {
						back.Body.Close()
					}
				}
				sent <- location
			}()
		}
	}()
	return sent
}

func (v *vendorAuth) login(say io.Writer, paste io.Reader) Login {
	server, _ := url.Parse(v.server.URL + "/mcp")
	return Login{Server: server, HTTP: v.http(), Port: 0, Say: say, Paste: paste, Wait: 20 * time.Second}
}

func TestSignInWithDynamicRegistration(t *testing.T) {
	v := newVendorAuth(t)
	said, say := io.Pipe()
	v.browser(t, said, true)
	signed, err := v.login(say, nil).SignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if signed.AccessToken != "access-1" || signed.OAuth.RefreshToken != "refresh-1" || signed.OAuth.ClientID != "registered-client" || v.registered != 1 {
		t.Fatalf("%+v %d", signed, v.registered)
	}
	if signed.OAuth.Resource != v.resource || signed.OAuth.ExpiresAt.Before(time.Now().Add(50*time.Minute)) {
		t.Fatalf("%+v", signed.OAuth)
	}
	// The scope the server asked for; PKCE with S256; the resource indicator.
	if v.authorized.Get("scope") != "repo:read" || v.authorized.Get("code_challenge_method") != "S256" || v.authorized.Get("resource") != v.resource || v.authorized.Get("state") == "" {
		t.Fatalf("%v", v.authorized)
	}
}

func TestSignInPrefersTheMetadataDocument(t *testing.T) {
	v := newVendorAuth(t)
	v.cimd = true
	said, say := io.Pipe()
	v.browser(t, said, true)
	login := v.login(say, nil)
	login.MetadataDocument = "https://nia.example/oauth/nia-edge-client.json"
	signed, err := login.SignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if signed.OAuth.ClientID != login.MetadataDocument || v.registered != 0 {
		t.Fatalf("%+v %d", signed.OAuth, v.registered)
	}
}

func TestSignInByPastingTheAddress(t *testing.T) {
	v := newVendorAuth(t)
	said, say := io.Pipe()
	sent := v.browser(t, said, false)
	paste, typed := io.Pipe()
	go func() {
		fmt.Fprintln(typed, <-sent)
		typed.Close()
	}()
	signed, err := v.login(say, paste).SignIn(context.Background())
	if err != nil || signed.AccessToken != "access-1" {
		t.Fatalf("%v %v", signed, err)
	}
}

func TestSignInRefusals(t *testing.T) {
	for name, change := range map[string]func(*vendorAuth){
		"no PKCE":          func(v *vendorAuth) { v.s256 = false },
		"another resource": func(v *vendorAuth) { v.resource = "https://other.example/mcp" },
		"no registration":  func(v *vendorAuth) { v.dcr = false },
	} {
		v := newVendorAuth(t)
		change(v)
		said, say := io.Pipe()
		go func() { _, _ = io.Copy(io.Discard, said) }()
		if _, err := v.login(say, nil).SignIn(context.Background()); err == nil {
			t.Errorf("%s: signed in", name)
		}
		say.Close()
		if len(v.challenges) != 0 {
			t.Errorf("%s: the browser was sent before the checks", name)
		}
	}
	// An answer with another state is not the answer to this sign-in.
	v := newVendorAuth(t)
	said, say := io.Pipe()
	sent := v.browser(t, said, false)
	paste, typed := io.Pipe()
	go func() {
		forged, _ := url.Parse(<-sent)
		query := forged.Query()
		query.Set("state", "forged")
		forged.RawQuery = query.Encode()
		fmt.Fprintln(typed, forged.String())
		typed.Close()
	}()
	if _, err := v.login(say, paste).SignIn(context.Background()); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("%v", err)
	}
	// A server that asks for no sign-in.
	open := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer open.Close()
	server, _ := url.Parse(open.URL + "/mcp")
	if _, err := (Login{Server: server, HTTP: open.Client(), Say: io.Discard}).SignIn(context.Background()); err == nil {
		t.Fatal("no 401, no sign-in")
	}
	// An authorization server whose endpoint is not HTTPS.
	if _, err := secure("http://evil.example/authorize"); err == nil {
		t.Fatal("HTTP outside the loopback")
	}
}

func TestTokenRenewed(t *testing.T) {
	v := newVendorAuth(t)
	said, say := io.Pipe()
	v.browser(t, said, true)
	signed, err := v.login(say, nil).SignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, _ := url.Parse(v.server.URL + "/mcp")
	var saved []string
	oauth := signed.OAuth
	client := &Client{
		Endpoint: Endpoint{Name: "github", URL: endpoint, Header: "Authorization", Value: "Bearer " + signed.AccessToken},
		HTTP:     v.http(),
		Renewer: &Renewer{HTTP: v.http(), OAuth: oauth, Save: func(access string, oauth OAuth) error {
			saved = append(saved, access+" "+oauth.RefreshToken)
			return nil
		}},
	}
	if _, err := client.Tools(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Revoked early: renewed once, kept, and the call goes through.
	v.mu.Lock()
	delete(v.accessValid, "access-1")
	v.mu.Unlock()
	client.mu.Lock()
	client.ready = false
	client.mu.Unlock()
	if _, err := client.Tools(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 || !strings.HasPrefix(saved[0], "access-") || !strings.Contains(saved[0], "refresh-access-") {
		t.Fatalf("the rotated refresh token is kept: %v", saved)
	}
	// Expired by its date: renewed before the call.
	client.Renewer.mu.Lock()
	client.Renewer.OAuth.ExpiresAt = time.Now().Add(-time.Hour)
	client.Renewer.mu.Unlock()
	if _, err := client.Tools(context.Background()); err != nil || len(saved) != 2 {
		t.Fatalf("%v %v", err, saved)
	}
	// The refresh token no longer works: the call fails, it says to sign in.
	v.mu.Lock()
	v.refresh = "gone"
	v.accessValid = map[string]bool{}
	v.mu.Unlock()
	if _, err := client.Tools(context.Background()); err == nil || !strings.Contains(err.Error(), "remote login") {
		t.Fatalf("%v", err)
	}
	for _, form := range v.tokenForms {
		if form.Get("resource") != v.resource {
			t.Fatalf("every token request names the resource: %v", form)
		}
	}
}

func TestChallenge(t *testing.T) {
	got := challenge(`Bearer error="insufficient_scope", scope="a b", resource_metadata="https://x/.well-known/oauth-protected-resource"`)
	if got["scope"] != "a b" || got["resource_metadata"] != "https://x/.well-known/oauth-protected-resource" || got["error"] != "insufficient_scope" {
		t.Fatalf("%v", got)
	}
	if len(challenge(`Basic realm="x"`)) != 0 {
		t.Fatal("not a Bearer challenge")
	}
}
