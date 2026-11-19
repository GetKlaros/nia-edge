package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GetKlaros/nia-edge/internal/state"
)

// A sign-in through a pasted address: the tokens go to the state file only.
func TestRemoteLoginKeepsTheTokensOutOfSight(t *testing.T) {
	const access, refresh = "gho_accessaccessaccessaccess0000", "ghr_refreshrefreshrefreshrefresh00"
	var vendor *httptest.Server
	vendor = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+vendor.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/mcp":
			answer(map[string]any{"resource": vendor.URL + "/mcp", "authorization_servers": []string{vendor.URL}})
		case "/.well-known/oauth-authorization-server":
			answer(map[string]any{"issuer": vendor.URL, "authorization_endpoint": vendor.URL + "/authorize", "token_endpoint": vendor.URL + "/token", "code_challenge_methods_supported": []string{"S256"}})
		case "/authorize":
			back, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			back.RawQuery = url.Values{"code": {"c"}, "state": {r.URL.Query().Get("state")}}.Encode()
			http.Redirect(w, r, back.String(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("client_id") != "pre-registered" || r.PostForm.Get("code_verifier") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			answer(map[string]any{"access_token": access, "token_type": "Bearer", "refresh_token": refresh, "expires_in": 600})
		default:
			http.NotFound(w, r)
		}
	}))
	defer vendor.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()

	path := filepath.Join(t.TempDir(), "state.json")
	saved := &state.State{NiaURL: "https://nia.example", Key: "nia_machine"}
	said, say := io.Pipe()
	paste, typed := io.Pipe()
	var printed strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(said)
		for scanner.Scan() {
			line := scanner.Text()
			printed.WriteString(line + "\n")
			if link := strings.TrimSpace(line); strings.HasPrefix(link, vendor.URL+"/authorize") {
				noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				go func() {
					response, err := noFollow.Get(link)
					if err != nil {
						t.Error(err)
						return
					}
					response.Body.Close()
					io.WriteString(typed, response.Header.Get("Location")+"\n")
				}()
			}
		}
	}()
	err = mcpLogin(saved, path, "github", vendor.URL+"/mcp", "pre-registered", false, port, paste, say)
	say.Close()
	<-done
	typed.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(printed.String(), access) || strings.Contains(printed.String(), refresh) {
		t.Fatalf("a token was shown: %s", printed.String())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "Bearer "+access) || !strings.Contains(string(raw), refresh) {
		t.Fatalf("%s", raw)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("%v", info.Mode())
	}
}
