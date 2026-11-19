package remotemcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/state"
)

// Signing in with the vendor, as the MCP authorization specification
// (2025-11-25) has a client do it: the server's protected resource metadata
// (RFC 9728) names its authorization server, whose metadata (RFC 8414 or
// OpenID Connect discovery) must offer PKCE with S256; the client is
// pre-registered, or nia-edge's Client ID Metadata Document, or registered
// dynamically (RFC 7591); the authorization code comes back to a loopback
// address with the state nia-edge sent, and is exchanged with its PKCE
// verifier and the resource indicator (RFC 8707) of the server. Every
// endpoint but the loopback one is HTTPS. The tokens are kept in the state
// file only, and the access token is renewed with the refresh token.

// OAuth is what nia-edge keeps to renew a server's access token.
type OAuth = state.RemoteOAuth

// Login is how to sign in with one server.
type Login struct {
	Server *url.URL
	HTTP   *http.Client
	// ClientID and ClientSecret are a client registered beforehand with the
	// vendor; empty to use the metadata document or dynamic registration.
	ClientID, ClientSecret string
	// MetadataDocument is the HTTPS URL of nia-edge's Client ID Metadata
	// Document (served by the Nia it enrolled with); empty to skip it.
	MetadataDocument string
	// Port is the loopback port the browser comes back to.
	Port int
	// Say receives the link to open; Paste may carry the address the
	// browser was sent back to, when it ran on another machine.
	Say   io.Writer
	Paste io.Reader
	// Wait bounds the sign-in; zero means ten minutes.
	Wait time.Duration
}

// Signed is the result of a sign-in.
type Signed struct {
	AccessToken string
	OAuth       OAuth
}

// secure accepts HTTPS, and HTTP on the loopback only.
func secure(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%q is not an absolute URL", raw)
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if ip := net.ParseIP(parsed.Hostname()); parsed.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return parsed, nil
	}
	return nil, fmt.Errorf("%s is not HTTPS", parsed.Host)
}

func getJSON(ctx context.Context, client *http.Client, raw string, into any) (bool, error) {
	target, err := secure(raw)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return false, fmt.Errorf("cannot reach %s", target.Host)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, nil
	}
	raw2, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw2) > 1<<20 {
		return false, fmt.Errorf("%s answered too much", target.Host)
	}
	if err := json.Unmarshal(raw2, into); err != nil {
		return false, fmt.Errorf("%s answered something that is not JSON", target.Host)
	}
	return true, nil
}

// challenge reads a Bearer WWW-Authenticate header's parameters.
func challenge(header string) map[string]string {
	out := map[string]string{}
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return out
	}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		key, value, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `"`) {
			end := strings.Index(value[1:], `"`)
			if end < 0 {
				break
			}
			out[key] = value[1 : end+1]
			rest = value[end+2:]
		} else {
			item, after, _ := strings.Cut(value, ",")
			out[key] = strings.TrimSpace(item)
			rest = after
		}
	}
	return out
}

type resourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

type serverMetadata struct {
	Issuer                    string   `json:"issuer"`
	AuthorizationEndpoint     string   `json:"authorization_endpoint"`
	TokenEndpoint             string   `json:"token_endpoint"`
	RegistrationEndpoint      string   `json:"registration_endpoint"`
	CodeChallengeMethods      []string `json:"code_challenge_methods_supported"`
	ClientIDMetadataDocuments bool     `json:"client_id_metadata_document_supported"`
	TokenEndpointAuthMethods  []string `json:"token_endpoint_auth_methods_supported"`
}

func trimSlash(raw string) string { return strings.TrimSuffix(raw, "/") }

// discover finds the server's resource, scope and authorization server.
func (l Login) discover(ctx context.Context) (resourceMetadata, string, serverMetadata, error) {
	var none serverMetadata
	// Unauthenticated, the server says where its metadata is.
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + Versions[0] + `","capabilities":{},"clientInfo":{"name":"nia-edge"}}}`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, l.Server.String(), body)
	if err != nil {
		return resourceMetadata{}, "", none, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := l.HTTP.Do(request)
	if err != nil {
		return resourceMetadata{}, "", none, fmt.Errorf("cannot reach %s", l.Server.Host)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		return resourceMetadata{}, "", none, fmt.Errorf("%s did not ask to sign in (it answered %d): use nia-edge mcp remote add with its token", l.Server.Host, response.StatusCode)
	}
	params := challenge(response.Header.Get("WWW-Authenticate"))
	candidates := []string{}
	if params["resource_metadata"] != "" {
		candidates = append(candidates, params["resource_metadata"])
	} else {
		origin := l.Server.Scheme + "://" + l.Server.Host
		if path := strings.TrimSuffix(l.Server.EscapedPath(), "/"); path != "" {
			candidates = append(candidates, origin+"/.well-known/oauth-protected-resource"+path)
		}
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource")
	}
	var prm resourceMetadata
	found := false
	for _, candidate := range candidates {
		if found, err = getJSON(ctx, l.HTTP, candidate, &prm); err != nil {
			return resourceMetadata{}, "", none, err
		}
		if found {
			break
		}
	}
	if !found || len(prm.AuthorizationServers) == 0 {
		return resourceMetadata{}, "", none, fmt.Errorf("%s publishes no protected resource metadata naming an authorization server", l.Server.Host)
	}
	// The metadata must be about this server (RFC 9728): its resource is the
	// server's URL, or a prefix of it at a path boundary.
	resource, err := secure(prm.Resource)
	server := trimSlash(l.Server.String())
	if err != nil || !(trimSlash(resource.String()) == server || strings.HasPrefix(server, trimSlash(resource.String())+"/")) {
		return resourceMetadata{}, "", none, fmt.Errorf("the metadata of %s is about another resource (%q)", l.Server.Host, prm.Resource)
	}
	prm.Resource = trimSlash(resource.String())
	scope := params["scope"]
	if scope == "" {
		scope = strings.Join(prm.ScopesSupported, " ")
	}
	metadata, err := l.authorizationServer(ctx, prm.AuthorizationServers[0])
	return prm, scope, metadata, err
}

// authorizationServer reads an issuer's metadata, in the order the
// specification gives, and checks it.
func (l Login) authorizationServer(ctx context.Context, issuer string) (serverMetadata, error) {
	parsed, err := secure(issuer)
	if err != nil {
		return serverMetadata{}, err
	}
	origin := parsed.Scheme + "://" + parsed.Host
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	urls := []string{origin + "/.well-known/oauth-authorization-server", origin + "/.well-known/openid-configuration"}
	if path != "" {
		urls = []string{
			origin + "/.well-known/oauth-authorization-server" + path,
			origin + "/.well-known/openid-configuration" + path,
			origin + path + "/.well-known/openid-configuration",
		}
	}
	for _, candidate := range urls {
		var metadata serverMetadata
		found, err := getJSON(ctx, l.HTTP, candidate, &metadata)
		if err != nil {
			return serverMetadata{}, err
		}
		if !found {
			continue
		}
		if trimSlash(metadata.Issuer) != trimSlash(issuer) {
			return serverMetadata{}, fmt.Errorf("the authorization server's metadata names another issuer (%q)", metadata.Issuer)
		}
		pkce := false
		for _, method := range metadata.CodeChallengeMethods {
			pkce = pkce || method == "S256"
		}
		if !pkce {
			return serverMetadata{}, errors.New("the authorization server does not offer PKCE with S256: nia-edge does not sign in without it")
		}
		for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint} {
			if _, err := secure(endpoint); err != nil {
				return serverMetadata{}, fmt.Errorf("an endpoint of the authorization server is not HTTPS: %w", err)
			}
		}
		if metadata.RegistrationEndpoint != "" {
			if _, err := secure(metadata.RegistrationEndpoint); err != nil {
				metadata.RegistrationEndpoint = ""
			}
		}
		return metadata, nil
	}
	return serverMetadata{}, fmt.Errorf("%s publishes no authorization server metadata", parsed.Host)
}

func random() string {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

// client picks how nia-edge is known to the authorization server.
func (l Login) client(ctx context.Context, metadata serverMetadata, redirect string) (id, secret string, err error) {
	switch {
	case l.ClientID != "":
		return l.ClientID, l.ClientSecret, nil
	case metadata.ClientIDMetadataDocuments && l.MetadataDocument != "":
		if _, err := secure(l.MetadataDocument); err != nil {
			return "", "", err
		}
		return l.MetadataDocument, "", nil
	case metadata.RegistrationEndpoint != "":
		body, _ := json.Marshal(map[string]any{
			"client_name":                "nia-edge",
			"redirect_uris":              []string{redirect},
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none",
		})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.RegistrationEndpoint, strings.NewReader(string(body)))
		if err != nil {
			return "", "", err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := l.HTTP.Do(request)
		if err != nil {
			return "", "", errors.New("cannot reach the registration endpoint")
		}
		defer response.Body.Close()
		var registered struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		if response.StatusCode/100 != 2 || json.Unmarshal(raw, &registered) != nil || registered.ClientID == "" {
			return "", "", fmt.Errorf("the authorization server refused to register nia-edge (%d)", response.StatusCode)
		}
		return registered.ClientID, registered.ClientSecret, nil
	}
	return "", "", errors.New("the authorization server offers no way for nia-edge to register: register a client with the vendor and give -client-id")
}

// SignIn runs the sign-in and returns the tokens.
func (l Login) SignIn(ctx context.Context) (*Signed, error) {
	wait := l.Wait
	if wait == 0 {
		wait = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	prm, scope, metadata, err := l.discover(ctx)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(l.Port)))
	if err != nil {
		return nil, fmt.Errorf("cannot listen on 127.0.0.1:%d for the way back: %w", l.Port, err)
	}
	defer listener.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)
	clientID, clientSecret, err := l.client(ctx, metadata, redirect)
	if err != nil {
		return nil, err
	}
	verifier, state := random(), random()
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {prm.Resource},
	}
	if scope != "" {
		query.Set("scope", scope)
	}
	authorize, _ := url.Parse(metadata.AuthorizationEndpoint)
	merged := authorize.Query()
	for key, values := range query {
		merged[key] = values
	}
	authorize.RawQuery = merged.Encode()
	fmt.Fprintf(l.Say, "Open this link in a browser and sign in with %s:\n\n  %s\n\n", authorize.Host, authorize.String())
	fmt.Fprintf(l.Say, "It comes back to %s. If the browser runs on another machine, paste here the address it was sent to.\n", redirect)

	codes := make(chan url.Values, 2)
	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			select {
			case codes <- r.URL.Query():
			default:
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "nia-edge received the answer: you can close this page.")
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	if l.Paste != nil {
		go func() {
			// Line by line: a pasted address ends with Enter, not with the input.
			lines := bufio.NewScanner(io.LimitReader(l.Paste, 64<<10))
			for lines.Scan() {
				if parsed, err := url.Parse(strings.TrimSpace(lines.Text())); err == nil && parsed.Query().Get("state") != "" {
					select {
					case codes <- parsed.Query():
					default:
					}
					return
				}
			}
		}()
	}
	var answer url.Values
	select {
	case answer = <-codes:
	case <-ctx.Done():
		return nil, errors.New("no answer from the browser in time")
	}
	// Only the answer to this request: the state nia-edge sent.
	if answer.Get("state") != state {
		return nil, errors.New("the answer does not carry the state nia-edge sent: it is not the answer to this sign-in")
	}
	if problem := answer.Get("error"); problem != "" {
		return nil, fmt.Errorf("the authorization server refused: %s", problem)
	}
	code := answer.Get("code")
	if code == "" {
		return nil, errors.New("the answer carries no code")
	}
	oauth := OAuth{TokenEndpoint: metadata.TokenEndpoint, ClientID: clientID, ClientSecret: clientSecret, Resource: prm.Resource, Scope: scope}
	token, err := exchange(ctx, l.HTTP, oauth, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
	if err != nil {
		return nil, err
	}
	oauth.RefreshToken = token.refresh
	oauth.ExpiresAt = token.expires
	return &Signed{AccessToken: token.access, OAuth: oauth}, nil
}

type issued struct {
	access, refresh string
	expires         time.Time
}

// exchange asks the token endpoint, with the client and the resource.
func exchange(ctx context.Context, client *http.Client, oauth OAuth, form url.Values) (*issued, error) {
	if _, err := secure(oauth.TokenEndpoint); err != nil {
		return nil, err
	}
	form.Set("resource", oauth.Resource)
	if oauth.ClientSecret == "" {
		form.Set("client_id", oauth.ClientID)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, oauth.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if oauth.ClientSecret != "" {
		request.SetBasicAuth(url.QueryEscape(oauth.ClientID), url.QueryEscape(oauth.ClientSecret))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("cannot reach the token endpoint")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("the token endpoint answered too much")
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	if json.Unmarshal(raw, &token) != nil {
		return nil, fmt.Errorf("the token endpoint answered %d, not JSON", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK || token.Error != "" {
		return nil, fmt.Errorf("the token endpoint refused (%d %s)", response.StatusCode, token.Error)
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") || strings.ContainsAny(token.AccessToken, "\r\n") {
		return nil, errors.New("the token endpoint gave no bearer token")
	}
	out := &issued{access: token.AccessToken, refresh: token.RefreshToken}
	if token.ExpiresIn > 0 {
		out.expires = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return out, nil
}

// Renewer keeps a server's access token fresh with its refresh token, and
// keeps what it renewed (Save) so that it survives a restart.
type Renewer struct {
	HTTP  *http.Client
	Save  func(access string, oauth OAuth) error
	mu    sync.Mutex
	OAuth OAuth
}

// due reports whether the token must be renewed before it is used.
func (r *Renewer) due(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.OAuth.ExpiresAt.IsZero() && now.After(r.OAuth.ExpiresAt.Add(-time.Minute))
}

// Renew gets a new access token; it fails without a refresh token.
func (r *Renewer) Renew(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.OAuth.RefreshToken == "" {
		return "", errors.New("the token expired and there is no refresh token: sign in again with nia-edge mcp remote login")
	}
	token, err := exchange(ctx, r.HTTP, r.OAuth, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.OAuth.RefreshToken}})
	if err != nil {
		return "", fmt.Errorf("the token could not be renewed (%w): sign in again with nia-edge mcp remote login", err)
	}
	// A server may rotate the refresh token: the new one replaces it.
	if token.refresh != "" {
		r.OAuth.RefreshToken = token.refresh
	}
	r.OAuth.ExpiresAt = token.expires
	if r.Save != nil {
		if err := r.Save(token.access, r.OAuth); err != nil {
			return "", fmt.Errorf("the renewed token could not be kept: %w", err)
		}
	}
	return token.access, nil
}
