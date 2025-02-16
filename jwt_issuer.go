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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// JWTIssuer is a Caddy module that issues JSON Web Tokens (JWT) after username
// and password authentication. It is intended to generate JWTs that are checked
// with https://github.com/ggicci/caddy-jwt, which provides the JWT Authentication.
type JWTIssuer struct {
	// SignKey is the base64 encoded secret key used to sign the JWTs.
	SignKey string

	// signKeyBytes is the base64 decoded secret key used to sign the JWTs.
	signKeyBytes []byte

	// Path to the user database file with username, password, and audience information
	UserDBPath string

	// Users map to hold the user database in memory
	users map[string]user

	// Mutex to protect the users map
	usersMutex *sync.RWMutex

	// JWT Issuer ("iss")
	TokenIssuer string

	// Default JWT lifetime unless the user has a specific token lifetime
	DefaultTokenLifetime time.Duration

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

	// Initialize the mutex if it's nil
	if m.usersMutex == nil {
		m.usersMutex = &sync.RWMutex{}
	}

	// Log the configuration values. Ensure that sensitive data such as keys are not logged
	m.logger.Info("JWT-Issuer plugin configured",
		zap.String("User database path", m.UserDBPath),
		zap.String("Token issuer", m.TokenIssuer),
		zap.String("Default JWT lifetime", m.DefaultTokenLifetime.String()),
	)

	// Attempt to load users from the specified database path
	if err := m.loadUsers(m.UserDBPath); err != nil {
		m.logger.Error("Failed to load users",
			zap.String("user_database", m.UserDBPath),
			zap.Error(err),
		)
		return err // Return the error to prevent the server from starting
	}

	var err error
	m.signKeyBytes, err = base64.StdEncoding.DecodeString(string(m.SignKey))
	if err != nil {
		m.logger.Error("Failed to decode sign key", zap.Error(err))
		return err
	}

	return nil
}

// Validate ensures the configuration is correct.
func (m *JWTIssuer) Validate() error {
	// Check if the base64 encoded sign key is set
	if m.SignKey == "" {
		return fmt.Errorf("SignKey must be defined")
	}

	// Check if the base64 decoded sign key has an appropriate length
	if len(m.signKeyBytes) < 32 { // 32 bytes is commonly recommended as a minimum for security
		return fmt.Errorf("decoded sign key must be at least 32 bytes long, check the base64 encoded sign key")
	}

	// Ensure the user database path is provided
	if m.UserDBPath == "" {
		return fmt.Errorf("user database path is required")
	}

	// Check that a token issuer is provided
	if m.TokenIssuer == "" {
		return fmt.Errorf("token issuer is required")
	}

	// Apply a default value of 15 minutes if the default token lifetime is not set
	if m.DefaultTokenLifetime == 0 {
		m.DefaultTokenLifetime = 15 * time.Minute
	}

	// Ensure the token lifetime is reasonable; for example, it should be positive
	if m.DefaultTokenLifetime <= 0 {
		return fmt.Errorf("default token lifetime must be a positive duration")
	}
	return nil
}

// ServeHTTP handles HTTP requests to issue JWT after user authentication.
func (m *JWTIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Retrieve the client IP address from the Caddy context.
	clientIP := getClientIP(r.Context(), r.RemoteAddr)

	// Create logger with common fields
	logger := m.logger.With(
		zap.String("client_ip", clientIP),
	)

	logger.Debug("Received JWT issuance request",
		zap.String("path", r.URL.Path),
		zap.String("method", r.Method),
	)

	// Only POST requests are allowed
	if r.Method != http.MethodPost {
		logger.Warn("Non-POST method attempted", zap.String("method", r.Method))
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return nil
	}

	// Decode the JSON body into the credentials struct
	var providedCredentials credentials
	if err := json.NewDecoder(r.Body).Decode(&providedCredentials); err != nil {
		logger.Error("Error decoding credentials", zap.Error(err))
		jsonError(w, http.StatusBadRequest, "Invalid request payload.")
		return nil
	}

	// Check if username was provided
	if providedCredentials.Username == "" {
		logger.Error("No username provided")
		jsonError(w, http.StatusBadRequest, "Missing username value")
		return nil
	}

	// Retrieve the user entry from the in-memory user database
	m.usersMutex.RLock()
	userEntry, exists := m.users[providedCredentials.Username]
	m.usersMutex.RUnlock()
	if !exists {
		logger.Warn("Authentication failed due to incorrect username",
			zap.String("username", providedCredentials.Username),
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
		logger.Warn("Authentication failed due to wrong password", zap.String("username", providedCredentials.Username))
		jsonError(w, http.StatusUnauthorized, "Unauthorized: Incorrect username or password")
		return nil
	}

	// Create the JWT
	tokenString, token, err := m.createJWT(userEntry)
	logger = logger.With(zap.String("username", userEntry.Username))
	if err != nil {
		logger.Error("Failed to create JWT", zap.Error(err))
		jsonError(w, http.StatusInternalServerError, "Internal server error")
		return nil
	}

	// Log successful JWT issuance
	logger.Info("Successfully issued JWT for user")

	// Log JWT details
	logJWTDetails(logger, tokenString, token)

	// Send the successful response with the JWT
	jsonResponse(w, http.StatusOK, apiResponse{
		Message: "Success",
		Token:   tokenString,
	})
	return nil
}

func logJWTDetails(logger *zap.Logger, tokenString string, token *jwt.Token) {
	logger.Debug("Encoded JWT", zap.String("jwt", tokenString))

	// Log the JWT claims
	expirationTime := time.Unix(token.Claims.(jwt.MapClaims)["exp"].(int64), 0)
	issuedAtTime := time.Unix(token.Claims.(jwt.MapClaims)["iat"].(int64), 0)
	logger.Info("JWT claims",
		zap.String("Subject", token.Claims.(jwt.MapClaims)["sub"].(string)),
		zap.String("Issuer", token.Claims.(jwt.MapClaims)["iss"].(string)),
		zap.Strings("Audience", token.Claims.(jwt.MapClaims)["aud"].([]string)),
		zap.String("JWT ID", token.Claims.(jwt.MapClaims)["jti"].(string)),
		zap.Time("Issued at", issuedAtTime),
		zap.Time("Expiration time", expirationTime),
	)
}

func (m *JWTIssuer) createJWT(user user) (string, *jwt.Token, error) {
	// Determine the token lifetime to use. By default, use the module's token lifetime.
	tokenLifetime := m.DefaultTokenLifetime
	// If the user has a specific token lifetime, use that instead
	if user.TokenLifetime != nil {
		tokenLifetime = *user.TokenLifetime
	}

	claims := jwt.MapClaims{
		"sub": user.Username,
		"iss": m.TokenIssuer,    // Issuer (used by issuer_whitelist )
		"aud": user.Audience,    // Audience (used by audience_whitelist)
		"jti": uuid.NewString(), // JWT ID
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(tokenLifetime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.signKeyBytes)
	return tokenString, token, err
}

// getClientIP retrieves the client IP address directly from the Caddy context.
func getClientIP(ctx context.Context, remoteAddr string) string {
	clientIP, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)["client_ip"]
	if ok {
		if ip, valid := clientIP.(string); valid {
			return ip
		}
	}
	// If the client IP is empty, extract it from the request's RemoteAddr.
	var err error
	clientIP, _, err = net.SplitHostPort(remoteAddr)
	if err != nil {
		// Use the complete RemoteAddr string as a last resort.
		clientIP = remoteAddr
	}
	return clientIP.(string)
}

// Interface guards to ensure JWTIssuer implements the necessary interfaces.
var (
	_ caddy.Module                = (*JWTIssuer)(nil)
	_ caddy.Provisioner           = (*JWTIssuer)(nil)
	_ caddy.Validator             = (*JWTIssuer)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTIssuer)(nil)
)
