// Package state keeps what nia-edge must remember between runs: where Nia
// is, and the key this machine received when it enrolled.
//
// The file holds a secret. It is written with mode 0600, replaced
// atomically, and refused when another user could read it.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/GetKlaros/nia-edge/internal/policy"
)

// State is the content of the state file.
type State struct {
	// NiaURL is the Nia this machine enrolled with.
	NiaURL    string `json:"nia_url"`
	MachineID string `json:"machine_id"`
	// Key is the machine's agent key. Nia keeps its hash only.
	Key          string    `json:"key"`
	Role         string    `json:"role"`
	Upstream     string    `json:"upstream"`
	KeyExpiresAt time.Time `json:"key_expires_at"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	// PolicyKey is the key that signs this machine's policy, as the server
	// gave it at enrollment. Nil when the server signs nothing.
	PolicyKey *policy.Key `json:"policy_key,omitempty"`
	// Provider is the model provider this machine calls itself. When it is
	// set, prompts and answers do not go through Nia: only the tool calls do.
	Provider *Provider `json:"provider,omitempty"`
	// MCP is the agent's MCP servers that run on this machine, each in its
	// own container, by name: their image, command and variables (their
	// tokens, which the agent never holds).
	MCP map[string]*MCPServer `json:"mcp,omitempty"`
}

// MCPServer is one of the agent's MCP servers that run on this machine.
type MCPServer struct {
	// Image is the image's ID, sha256:<64 hex>: it fixes the server's code.
	Image string `json:"image"`
	// Ref is where the image came from, for people: it decides nothing.
	Ref     string            `json:"ref,omitempty"`
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
}

// ErrNotEnrolled reports that there is no state file yet.
var ErrNotEnrolled = errors.New("this machine is not enrolled")

// Load reads the state file. It fails when the file is missing
// (ErrNotEnrolled), readable by another user, or not what Save wrote.
func Load(path string) (*State, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s holds the machine key and is readable by other users (mode %04o): run chmod 600 on it", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s is not a nia-edge state file: %w", path, err)
	}
	if s.NiaURL == "" || s.MachineID == "" || s.Key == "" {
		return nil, fmt.Errorf("%s is incomplete: enroll this machine again", path)
	}
	return &s, nil
}

// Save writes the state file, mode 0600, by writing a temporary file in the
// same directory and renaming it over the old one, so a crash leaves either
// the old state or the new one, never half of a key.
func Save(path string, s *State) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// CreateTemp creates the file with mode 0600.
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// CheckWritable reports whether Save could write the state file, without
// touching it: it creates and removes a file next to it.
func CheckWritable(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	probe.Close()
	return os.Remove(probe.Name())
}

// Provider is a model provider and the credential to call it.
type Provider struct {
	// BaseURL ends in /v1, or wherever the provider serves its API.
	BaseURL string `json:"base_url"`
	// Key is the provider's API key. It never reaches the agent.
	Key string `json:"key"`
	// Format is "openai" (Authorization: Bearer) or "anthropic" (x-api-key).
	Format string `json:"format"`
	// SessionHeader names a header that carries a stable id of the
	// conversation, for a provider that routes by it; empty for none.
	SessionHeader string `json:"session_header,omitempty"`
}
