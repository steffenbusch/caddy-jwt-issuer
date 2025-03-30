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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

// user struct to hold username, password, audience, and token lifetime information
type user struct {
	Username        string
	Password        string
	Audience        []string
	TokenLifetime   *time.Duration
	TokenValidUntil string
	TOTPSecret      string
	MetaClaims      map[string]any
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

// validateUserEntry ensures the user entry is correct.
func (m *JWTIssuer) validateUserEntry(user user, username, clientIP string) error {
	// Lock the users map for reading
	m.usersMutex.RLock()
	defer m.usersMutex.RUnlock()

	if user.Password == "" {
		m.logger.Error("User database entry missing password",
			zap.String("user_database", m.UserDBPath),
			zap.String("username", username),
			zap.String("clientIP", clientIP),
		)
		return fmt.Errorf("user database entry missing password")
	}

	if len(user.Audience) == 0 || user.Audience[0] == "" {
		m.logger.Error("User database entry missing audience",
			zap.String("user_database", m.UserDBPath),
			zap.String("username", username),
			zap.String("clientIP", clientIP),
		)
		return fmt.Errorf("user database entry missing audience")
	}

	return nil
}

// loadUsers loads users from the specified file path.
func (m *JWTIssuer) loadUsers(filePath string) error {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Temporary map to hold the data from the JSON file
	tempUsers := make(map[string]struct {
		Password        string         `json:"password"`
		Audience        []string       `json:"audience"`
		TokenLifetime   *string        `json:"token_lifetime"`
		TokenValidUntil string         `json:"token_valid_until"`
		TOTPSecret      string         `json:"totp_secret"`
		MetaClaims      map[string]any `json:"meta_claims"`
	})

	if err := json.Unmarshal(file, &tempUsers); err != nil {
		return err
	}

	// Lock the users map for writing
	m.usersMutex.Lock()
	defer m.usersMutex.Unlock()

	// Reinitialize the users map to clear old data
	m.users = make(map[string]user)

	// Populate the users map and set the Username field
	for username, userData := range tempUsers {
		var tokenLifetime *time.Duration
		if userData.TokenLifetime != nil {
			duration, err := time.ParseDuration(*userData.TokenLifetime)
			if err != nil {
				return fmt.Errorf("invalid token lifetime format for user %s: %v", username, err)
			}
			tokenLifetime = &duration
		}
		m.users[username] = user{
			Username:        username,
			Password:        userData.Password,
			Audience:        userData.Audience,
			TokenLifetime:   tokenLifetime,
			TOTPSecret:      userData.TOTPSecret,
			MetaClaims:      userData.MetaClaims,
			TokenValidUntil: userData.TokenValidUntil,
		}
	}

	m.logger.Info("Loaded users from user database",
		zap.String("user_database", filePath),
		zap.Int("user_count", len(m.users)),
	)

	return nil
}
