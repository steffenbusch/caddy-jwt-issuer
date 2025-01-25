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

	"go.uber.org/zap"
)

// user struct to hold username, password, and audience information
type user struct {
	Username string
	Password string
	Audience []string
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// validateUserEntry ensures the user entry is correct.
func (m *JWTIssuer) validateUserEntry(user user, username, clientIP string) error {
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

	// Reinitialize the users map to clear old data
	m.users = make(map[string]user)

	// Temporary map to hold the data from the JSON file
	tempUsers := make(map[string]user)

	if err := json.Unmarshal(file, &tempUsers); err != nil {
		return err
	}

	// Populate the users map and set the Username field
	for username, userData := range tempUsers {
		userData.Username = username
		m.users[username] = userData
	}

	m.logger.Info("Loaded users from user database",
		zap.String("user_database", filePath),
		zap.Int("user_count", len(m.users)),
	)

	return nil
}
