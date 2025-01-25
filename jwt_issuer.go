// Copyright 2025 Steffen Busch

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwtissuer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// JWTIssuer implements an HTTP handler that issues JWTs after authentication.
type JWTIssuer struct {
	// SignKey is the secret key used to sign the JWTs.
	SignKey []byte

	// Path to the user database file with username, password, and audience information
	UserDBPath string

	// Users map to hold the user database in memory
	users map[string]user

	// JWT Issuer ("iss")
	TokenIssuer string

	// JWT lifetime
	TokenLifetime time.Duration

	// logger provides structured logging for the module.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (JWTIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt_issuer",
		New: func() caddy.Module { return new(JWTIssuer) },
	}
}

// Provision sets up the module, initializes the logger, and applies default values.
func (m *JWTIssuer) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// Log the configuration values. Ensure that sensitive data such as keys are not logged
	m.logger.Info("JWT-Issuer plugin configured",
		zap.String("User database path", m.UserDBPath),
		zap.String("Token issuer", m.TokenIssuer),
		zap.String("JWT lifetime", m.TokenLifetime.String()),
	)

	// Attempt to load users from the specified database path
	if err := m.loadUsers(m.UserDBPath); err != nil {
		m.logger.Error("Failed to load users",
			zap.String("user_database", m.UserDBPath),
			zap.Error(err),
		)
		return err // Return the error to prevent the server from starting
	}

	return nil
}

// Validate ensures the configuration is correct.
func (m *JWTIssuer) Validate() error {
	// Check if the secret key is set and has an appropriate length
	if len(m.SignKey) < 32 { // 32 bytes is commonly recommended as a minimum for security
		return fmt.Errorf("sign key must be at least 32 bytes long")
	}

	// Ensure the user database path is provided
	if m.UserDBPath == "" {
		return fmt.Errorf("user database path is required")
	}

	// Check that a token issuer is provided
	if m.TokenIssuer == "" {
		return fmt.Errorf("token issuer is required")
	}

	// Ensure the token lifetime is reasonable; for example, it should be positive
	if m.TokenLifetime <= 0 {
		return fmt.Errorf("token lifetime must be a positive duration")
	}
	return nil
}

// ServeHTTP handles HTTP requests to issue JWT after user authentication.
func (m *JWTIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Retrieve the client IP using Caddy's helpers or from the request directly
	clientIP := getClientIP(r.Context())
	if clientIP == "" {
		clientIP = r.RemoteAddr // Fallback to remote address if no contextual IP found
	}

	m.logger.Debug("Received JWT issuance request",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
		zap.String("clientIP", clientIP),
	)

	// Only POST requests are allowed
	if r.Method != http.MethodPost {
		m.logger.Warn("Non-POST method attempted", zap.String("method", r.Method), zap.String("clientIP", clientIP))
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return nil
	}

	// Decode the JSON body into the credentials struct
	var providedCredentials credentials
	if err := json.NewDecoder(r.Body).Decode(&providedCredentials); err != nil {
		m.logger.Error("Error decoding credentials", zap.Error(err), zap.String("clientIP", clientIP))
		jsonError(w, http.StatusBadRequest, "Invalid request payload.")
		return nil
	}

	// Check if username was provided
	if providedCredentials.Username == "" {
		m.logger.Error("No username provided", zap.String("clientIP", clientIP))
		jsonError(w, http.StatusBadRequest, "Missing username value")
		return nil
	}

	// Retrieve the user entry from the in-memory user database
	userEntry, exists := m.users[providedCredentials.Username]
	if !exists {
		m.logger.Warn("Authentication failed due to incorrect username",
			zap.String("username", providedCredentials.Username),
			zap.String("clientIP", clientIP),
		)
		jsonError(w, http.StatusUnauthorized, "Unauthorized: Incorrect username or password")
		return nil
	}

	// Validate the user entry for missing fields
	if err := m.validateUserEntry(userEntry, providedCredentials.Username, clientIP); err != nil {
		jsonError(w, http.StatusInternalServerError, "Internal server error")
		return nil
	}

	// Verify the provided password against the stored hash
	if bcrypt.CompareHashAndPassword([]byte(userEntry.Password), []byte(providedCredentials.Password)) != nil {
		m.logger.Warn("Authentication failed due to wrong password", zap.String("username", providedCredentials.Username), zap.String("clientIP", clientIP))
		jsonError(w, http.StatusUnauthorized, "Unauthorized: Incorrect username or password")
		return nil
	}

	// Create the JWT token
	tokenString, token, err := m.createJWT(userEntry)
	if err != nil {
		m.logger.Error("Failed to create JWT", zap.Error(err), zap.String("username", userEntry.Username))
		jsonError(w, http.StatusInternalServerError, "Internal server error")
		return nil
	}

	// Log successful JWT issuance
	m.logger.Info("Successfully issued JWT for user", zap.String("username", userEntry.Username), zap.String("clientIP", clientIP))

	// Log JWT details if debug level is enabled
	if m.logger.Core().Enabled(zap.DebugLevel) {
		logJWTDetails(m, userEntry, tokenString, token)
	}

	// Send the successful response with the JWT token
	jsonResponse(w, http.StatusOK, apiResponse{
		Message: "Success",
		Token:   tokenString,
	})
	return nil
}

func logJWTDetails(m *JWTIssuer, user user, tokenString string, token *jwt.Token) {
	m.logger.Debug("Encoded JWT", zap.String("username", user.Username), zap.String("jwt", tokenString))

	headerJSON, err := json.Marshal(token.Header)
	if err == nil {
		m.logger.Debug("Decoded JWT header", zap.String("username", user.Username), zap.ByteString("header", headerJSON))
	}

	claimsJSON, err := json.Marshal(token.Claims)
	if err == nil {
		m.logger.Debug("Decoded JWT claims", zap.String("username", user.Username), zap.ByteString("claims", claimsJSON))
	}
}

func (m *JWTIssuer) createJWT(user user) (string, *jwt.Token, error) {
	claims := jwt.MapClaims{
		"sub": user.Username,
		"aud": user.Audience,
		"iss": m.TokenIssuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(m.TokenLifetime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.SignKey)
	return tokenString, token, err
}

// getClientIP retrieves the client IP address directly from the Caddy context.
func getClientIP(ctx context.Context) string {
	clientIP, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)["client_ip"]
	if ok {
		if ip, valid := clientIP.(string); valid {
			return ip
		}
	}
	return ""
}

// Interface guards to ensure JWTIssuer implements the necessary interfaces.
var (
	_ caddy.Module                = (*JWTIssuer)(nil)
	_ caddy.Provisioner           = (*JWTIssuer)(nil)
	_ caddy.Validator             = (*JWTIssuer)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTIssuer)(nil)
)
