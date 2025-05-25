package jwtissuer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"
)

func createTestUserDBFile(t *testing.T, users map[string]user) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "userdb-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpfile.Close()
	enc := json.NewEncoder(tmpfile)
	if err := enc.Encode(users); err != nil {
		t.Fatal(err)
	}
	return tmpfile.Name()
}

func TestJWTIssuer_Provision_Validate(t *testing.T) {
	// Create a dummy sign key (32 bytes, base64)
	signKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	// Create a bcrypt password hash
	pw, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 14)
	users := map[string]user{
		"alice": {
			Username: "alice",
			Password: string(pw),
			Audience: []string{"testaud"},
		},
	}
	userDB := createTestUserDBFile(t, users)
	defer os.Remove(userDB)

	issuer := &JWTIssuer{
		SignKey:              signKey,
		UserDBPath:           userDB,
		TokenIssuer:          "test-issuer",
		DefaultTokenLifetime: 10 * time.Minute,
	}
	// Set up logger for testing
	issuer.logger = zaptest.NewLogger(t)

	// Provision should load users and decode sign key
	// Use a stub caddy.Context for testing
	var stubCaddyCtx caddy.Context
	if err := issuer.Provision(stubCaddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	// Validate should succeed
	if err := issuer.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
}

func TestJWTIssuer_ServeHTTP_Success(t *testing.T) {
	signKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	pw, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 14)
	users := map[string]user{
		"bob": {
			Username: "bob",
			Password: string(pw),
			Audience: []string{"testaud"},
		},
	}
	userDB := createTestUserDBFile(t, users)
	defer os.Remove(userDB)

	issuer := &JWTIssuer{
		SignKey:              signKey,
		UserDBPath:           userDB,
		TokenIssuer:          "test-issuer",
		DefaultTokenLifetime: 10 * time.Minute,
		EnableCookie:         true,
		CookieName:           "jwt_auth",
	}
	issuer.logger = zaptest.NewLogger(t)
	var stubCaddyCtx caddy.Context
	if err := issuer.Provision(stubCaddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Prepare request
	body, _ := json.Marshal(credentials{
		Username: "bob",
		Password: "testpass",
	})
	req := httptest.NewRequest(http.MethodPost, "/jwt", bytes.NewReader(body))

	// Injecting mock Caddy context with client_ip and a basic replacer
	caddyVars := map[string]any{
		"client_ip": "10.1.2.3",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, caddyVars)
	repl := caddy.NewReplacer()
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	// ServeHTTP should succeed and return a token
	err := issuer.ServeHTTP(rr, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}

	var resp apiResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("Expected token in response")
	}

	// Check cookie
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "jwt_auth" {
			found = true
			break
		}
	}
	if !found {
		t.Error("JWT cookie not set")
	}
}

func TestJWTIssuer_ServeHTTP_BadPassword(t *testing.T) {
	signKey := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	pw, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 14)
	users := map[string]user{
		"bob": {
			Username: "bob",
			Password: string(pw),
			Audience: []string{"testaud"},
		},
	}
	userDB := createTestUserDBFile(t, users)
	defer os.Remove(userDB)

	issuer := &JWTIssuer{
		SignKey:              signKey,
		UserDBPath:           userDB,
		TokenIssuer:          "test-issuer",
		DefaultTokenLifetime: 10 * time.Minute,
	}
	issuer.logger = zaptest.NewLogger(t)
	var stubCaddyCtx caddy.Context
	if err := issuer.Provision(stubCaddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	body, _ := json.Marshal(credentials{
		Username: "bob",
		Password: "wrongpass",
	})
	req := httptest.NewRequest(http.MethodPost, "/jwt", bytes.NewReader(body))

	// Injecting mock Caddy context *after* req is created
	caddyVars := map[string]any{
		"client_ip": "10.1.2.3",
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, caddyVars)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()

	err := issuer.ServeHTTP(rr, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestCaddyfileJWTIssuer(t *testing.T) {
	// Create a temporary user DB file for the test
	pw, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 14)
	users := map[string]user{
		"testuser": {
			Username: "testuser",
			Password: string(pw),
			Audience: []string{"testaud"},
		},
	}
	userDB := createTestUserDBFile(t, users)
	defer os.Remove(userDB)

	caddyfile := `
	{
		skip_install_trust
		admin localhost:2999
		http_port 8081
	}
	:8081 {
		handle /jwt {
			jwt_issuer {
				sign_key "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
				user_db_path "` + userDB + `"
				token_issuer "test-issuer"
			}
		}
		handle {
			respond "ok"
		}
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(caddyfile, "caddyfile")

	// Test GET (should be 405)
	req, err := http.NewRequest("GET", "http://localhost:8081/jwt", nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	resp := tester.AssertResponseCode(req, 405)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Method Not Allowed") {
		t.Errorf("Expected method not allowed, got: %s", string(body))
	}

	// Test POST with invalid body (should be 400)
	req, err = http.NewRequest("POST", "http://localhost:8081/jwt", strings.NewReader("notjson"))
	if err != nil {
		t.Fatalf("Failed to create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp = tester.AssertResponseCode(req, 400)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Invalid request payload") {
		t.Errorf("Expected invalid request payload, got: %s", string(body))
	}

	// Test fallback handler
	req, err = http.NewRequest("GET", "http://localhost:8081/", nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	resp = tester.AssertResponseCode(req, 200)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ok") {
		t.Errorf("Expected ok, got: %s", string(body))
	}
}
