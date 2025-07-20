package matchers

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/zaptest"
)

func createTempBlocklistFile(t *testing.T, tokens []string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "blocklist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		_, _ = tmpfile.WriteString(token + "\n")
	}
	tmpfile.Close()
	return tmpfile.Name()
}

// Helper to create a request with a replacer context
func makeReqWithToken(token string) *http.Request {
	req, _ := http.NewRequest("GET", "/", nil)
	repl := caddy.NewReplacer()
	repl.Set("token", token)
	ctx := req.Context()
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)
	return req
}

func TestTokenIsBlocked_Match(t *testing.T) {
	blockedTokens := []string{"blockedtoken1", "blockedtoken2"}
	blocklistFile := createTempBlocklistFile(t, blockedTokens)
	defer os.Remove(blocklistFile)

	m := &TokenIsBlocked{
		BlocklistFile: blocklistFile,
		Placeholder:   "{token}",
	}
	// Set up logger for testing
	m.logger = zaptest.NewLogger(t)

	// Use a stub caddy.Context for Provision
	var stubCaddyCtx caddy.Context
	if err := m.Provision(stubCaddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer m.Cleanup()

	// Should match blocked tokens
	for _, token := range blockedTokens {
		req := makeReqWithToken(token)
		if !m.Match(req) {
			t.Errorf("Expected token %q to be blocked", token)
		}
	}

	// Should not match unblocked token
	req := makeReqWithToken("notblocked")
	if m.Match(req) {
		t.Errorf("Expected token %q to NOT be blocked", "notblocked")
	}
}

func TestTokenIsBlocked_UnmarshalCaddyfile(t *testing.T) {
	input := `
	token_is_blocked {
		blocklist_file /tmp/blocklist.txt
		placeholder {mytoken}
	}
	`
	d := caddyfile.NewTestDispenser(input)
	var m TokenIsBlocked
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}
	if m.BlocklistFile != "/tmp/blocklist.txt" {
		t.Errorf("BlocklistFile = %q, want /tmp/blocklist.txt", m.BlocklistFile)
	}
	if m.Placeholder != "{mytoken}" {
		t.Errorf("Placeholder = %q, want {mytoken}", m.Placeholder)
	}
}

func TestTokenIsBlocked_FileWatcherReload(t *testing.T) {
	blockedTokens := []string{"tokenA"}
	blocklistFile := createTempBlocklistFile(t, blockedTokens)
	defer os.Remove(blocklistFile)

	m := &TokenIsBlocked{
		BlocklistFile: blocklistFile,
		Placeholder:   "{token}",
	}
	m.logger = zaptest.NewLogger(t)
	var stubCaddyCtx caddy.Context
	if err := m.Provision(stubCaddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer m.Cleanup()

	// Initially blocked
	if !m.Match(makeReqWithToken("tokenA")) {
		t.Errorf("Expected tokenA to be blocked")
	}
	// Not blocked
	if m.Match(makeReqWithToken("tokenB")) {
		t.Errorf("Expected tokenB to NOT be blocked")
	}

	// Append tokenB to blocklist file
	f, err := os.OpenFile(blocklistFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Failed to open blocklist file: %v", err)
	}
	_, _ = f.WriteString("tokenB\n")
	f.Close()

	// Wait for watcher to reload (should be quick, but allow up to 500ms)
	found := false
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		if m.Match(makeReqWithToken("tokenB")) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected tokenB to be blocked after file update")
	}
}

func TestTokenIsBlocked_ProvisionErrors(t *testing.T) {
	// Missing blocklist file path
	m := &TokenIsBlocked{}
	var stubCaddyCtx caddy.Context
	err := m.Provision(stubCaddyCtx)
	if err == nil || err.Error() != "blocklist_file must be set" {
		t.Errorf("Expected error for missing blocklist_file, got: %v", err)
	}

	m = &TokenIsBlocked{
		BlocklistFile: "/nonexistent/blocklist.txt",
	}
	m.logger = zaptest.NewLogger(t)
	// Should fail to add watcher to non-existent directory
	err = m.Provision(stubCaddyCtx)
	if err == nil {
		t.Errorf("Expected error for invalid watcher directory, got nil")
	}
}

func TestTokenIsBlocked_loadBlocklistError(t *testing.T) {
	// Try loading from a non-existent file
	m := &TokenIsBlocked{
		BlocklistFile: "/nonexistent/file.txt",
	}
	m.logger = zaptest.NewLogger(t)
	err := m.loadBlocklist()
	if err == nil {
		t.Errorf("Expected error when loading non-existent blocklist file, got nil")
	}
}
