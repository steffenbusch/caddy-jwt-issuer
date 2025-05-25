package jwtissuer

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestValidateUserEntry(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	jwtIssuer := &JWTIssuer{
		logger:     logger,
		usersMutex: &sync.RWMutex{},
	}

	tests := []struct {
		name     string
		user     user
		username string
		clientIP string
		wantErr  bool
	}{
		{
			name: "Valid user entry",
			user: user{
				Username: "testuser",
				Password: "password",
				Audience: []string{"audience1"},
			},
			username: "testuser",
			clientIP: "127.0.0.1",
			wantErr:  false,
		},
		{
			name: "Missing password",
			user: user{
				Username: "testuser",
				Audience: []string{"audience1"},
			},
			username: "testuser",
			clientIP: "127.0.0.1",
			wantErr:  true,
		},
		{
			name: "Missing audience",
			user: user{
				Username: "testuser",
				Password: "password",
			},
			username: "testuser",
			clientIP: "127.0.0.1",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := jwtIssuer.validateUserEntry(tt.user, tt.username, tt.clientIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUserEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadUsers(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	jwtIssuer := &JWTIssuer{
		logger:     logger,
		users:      make(map[string]user),
		usersMutex: &sync.RWMutex{},
	}

	// Create a temporary JSON file with user data
	userData := map[string]struct {
		Password      string   `json:"password"`
		Audience      []string `json:"audience"`
		TokenLifetime *string  `json:"token_lifetime"`
	}{
		"testuser": {
			Password: "password",
			Audience: []string{"audience1"},
			TokenLifetime: func() *string {
				s := "1h"
				return &s
			}(),
		},
	}

	file, err := os.CreateTemp("", "users.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	if err := json.NewEncoder(file).Encode(userData); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	file.Close()

	if err := jwtIssuer.loadUsers(file.Name()); err != nil {
		t.Errorf("loadUsers() error = %v", err)
	}

	if len(jwtIssuer.users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(jwtIssuer.users))
	}

	user, exists := jwtIssuer.users["testuser"]
	if !exists {
		t.Errorf("Expected user 'testuser' to exist")
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got %s", user.Username)
	}

	if user.Password != "password" {
		t.Errorf("Expected password 'password', got %s", user.Password)
	}

	if len(user.Audience) != 1 || user.Audience[0] != "audience1" {
		t.Errorf("Expected audience 'audience1', got %v", user.Audience)
	}

	expectedDuration, _ := time.ParseDuration("1h")
	if user.TokenLifetime == nil || *user.TokenLifetime != expectedDuration {
		t.Errorf("Expected token lifetime '1h', got %v", user.TokenLifetime)
	}
}
