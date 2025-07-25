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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/olebedev/when"
	"github.com/olebedev/when/rules/en"
	"go.uber.org/zap"
)

// predefinedClaims returns a map of predefined JWT claims that cannot be overridden.
func predefinedClaims() map[string]bool {
	return map[string]bool{
		"sub": true,
		"iss": true,
		"aud": true,
		"jti": true,
		"iat": true,
		"nbf": true,
		"exp": true,
		"ip":  true,
	}
}

func logJWTDetails(logger *zap.Logger, tokenString string, token *jwt.Token) {
	logger.Debug("Encoded JWT", zap.String("jwt", tokenString))

	// Log the JWT claims
	claims := token.Claims.(jwt.MapClaims)
	expirationTime := time.Unix(claims["exp"].(int64), 0)
	issuedAtTime := time.Unix(claims["iat"].(int64), 0)

	logger.Info("JWT claims",
		zap.String("Subject", claims["sub"].(string)),
		zap.String("Issuer", claims["iss"].(string)),
		zap.Strings("Audience", claims["aud"].([]string)),
		zap.String("JWT ID", claims["jti"].(string)),
		zap.Time("Issued at", issuedAtTime),
		zap.Time("Expiration time", expirationTime),
	)

	// Collect meta_claims into a map
	metaClaims := make(map[string]any)
	for key, value := range claims {
		if !predefinedClaims()[key] {
			metaClaims[key] = value
		}
	}

	// Log all meta_claims in a single log event
	if len(metaClaims) > 0 {
		logger.Info("Meta claims", zap.Any("meta_claims", metaClaims))
	}
}

// determineTokenLifetime calculates the token lifetime for a given user.
// It prioritizes the user's specific token settings over the module's default settings.
//
// The function follows this order of precedence:
//  1. If the user has a specific "token valid until" time (`user.TokenValidUntil`), it is parsed
//     and used if it represents a future time. If parsing fails or the time is in the past,
//     it will not be used.
//  2. If the user has a specific token lifetime (`user.TokenLifetime`), it is used.
//  3. If neither of the above is provided, the module's default token lifetime is used.
func (m *JWTIssuer) determineTokenLifetime(user user) time.Duration {
	// By default, use the module's token lifetime
	tokenLifetime := m.DefaultTokenLifetime

	// If the user has a specific token lifetime, use that instead
	if user.TokenLifetime != nil && *user.TokenLifetime > 0 {
		tokenLifetime = *user.TokenLifetime
	}

	// However, if the user has a specific token-valid-until time, parse and use it instead
	if user.TokenValidUntil != "" {
		w := when.New(nil)
		w.Add(en.All...)
		result, err := w.Parse(user.TokenValidUntil, time.Now())
		if err != nil || result == nil {
			m.logger.Error("Failed to parse token valid until time",
				zap.String("username", user.Username),
				zap.String("token_valid_until", user.TokenValidUntil),
				zap.Bool("result is nil", result == nil),
				zap.Error(err),
			)
		} else if time.Until(result.Time) > 0 {
			// If the result time is in the future, use it as the token lifetime
			tokenLifetime = time.Until(result.Time)
			m.logger.Debug("Token valid until time parsed successfully",
				zap.String("username", user.Username),
				zap.String("token_valid_until", user.TokenValidUntil),
				zap.String("result_text", result.Text),
				zap.Time("result_time", result.Time),
			)
		} else {
			m.logger.Error("Token valid until time is in the past",
				zap.String("username", user.Username),
				zap.String("token_valid_until", user.TokenValidUntil),
				zap.String("result_text", result.Text),
				zap.Time("result_time", result.Time),
			)
		}
	}

	return tokenLifetime
}

func (m *JWTIssuer) createJWT(user user, clientIP string, ctx context.Context) (string, *jwt.Token, error) {
	// Determine the token lifetime
	tokenLifetime := m.determineTokenLifetime(user)

	claims := jwt.MapClaims{
		"sub": user.Username,
		"iss": m.TokenIssuer,    // Issuer (used by issuer_whitelist )
		"aud": user.Audience,    // Audience (used by audience_whitelist)
		"jti": uuid.NewString(), // JWT ID
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(tokenLifetime).Unix(),
		"ip":  clientIP, // Include client IP as a claim
	}

	// Fetch replacer from the request context
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// Add meta_claims to the JWT claims, excluding predefined claims
	for key, value := range user.MetaClaims {
		if !predefinedClaims()[key] {
			if strValue, ok := value.(string); ok {
				// Replace known placeholders in the meta_claim value
				// unknown placeholders are left as-is
				value = repl.ReplaceKnown(strValue, "")
			}
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.signKeyBytes)
	return tokenString, token, err
}
