package matchers

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// TokenIsBlocked is a Caddy matcher that checks if a JWT, typically its JTI, is in a blocklist file.
// It uses a file watcher to reload the blocklist when the file changes.
type TokenIsBlocked struct {
	// BlocklistFile is the path to the blocklist file.
	// Each line in the file should contain a token to be blocked.
	// If the file does not exist, it will be created.
	// The file is reloaded when it changes.
	BlocklistFile string `json:"blocklist_file,omitempty"`

	// Placeholder refers to the name of the placeholder that contains the token, typically the JTI.
	// It defaults to "{http.auth.user.jti}" if not set.
	Placeholder string `json:"placeholder,omitempty"`

	blocked atomic.Value // Holds map[string]struct{}
	watcher *fsnotify.Watcher
	logger  *zap.Logger
}

func (TokenIsBlocked) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.token_is_blocked",
		New: func() caddy.Module { return new(TokenIsBlocked) },
	}
}

func (m *TokenIsBlocked) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "blocklist_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BlocklistFile = d.Val()
			case "placeholder":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Placeholder = d.Val()
			default:
				return d.Errf("unknown option: %s", d.Val())
			}
		}
	}
	return nil
}

func (m *TokenIsBlocked) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.BlocklistFile == "" {
		return errors.New("blocklist_file must be set")
	}

	if m.Placeholder == "" {
		m.Placeholder = "{http.auth.user.jti}"
	}

	// Initialize the blocked map
	m.blocked.Store(make(map[string]struct{}))

	if _, err := os.Stat(m.BlocklistFile); os.IsNotExist(err) {
		file, createErr := os.Create(m.BlocklistFile)
		if createErr != nil {
			return fmt.Errorf("failed to create blocklist file: %w", createErr)
		}
		file.Close()
		m.logger.Info("Blocklist file created", zap.String("file", m.BlocklistFile))
	}

	if err := m.loadBlocklist(); err != nil {
		return fmt.Errorf("initial blocklist load failed: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = watcher

	// Monitor the parent directory of the blocklist file instead of the file itself.
	// This is because many programs update files atomically by replacing them, which
	// can cause the watcher to lose track of the file. Monitoring the parent directory
	// ensures that we can detect changes even if the file is replaced.
	// Reference: https://pkg.go.dev/github.com/fsnotify/fsnotify#readme-watching-a-file-doesn-t-work-well
	blocklistDir := filepath.Dir(m.BlocklistFile)
	if err := m.watcher.Add(blocklistDir); err != nil {
		return fmt.Errorf("watching blocklist directory failed: %w", err)
	}

	go m.watchDirectoryLoop()

	return nil
}

func (m *TokenIsBlocked) Cleanup() error {
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}

func (m *TokenIsBlocked) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	token := repl.ReplaceAll(m.Placeholder, "")

	if token == "" {
		m.logger.Warn("No token value resolved from placeholder", zap.String("placeholder", m.Placeholder))
		return false
	}

	// Load the current blocked map atomically
	blockedMap := m.blocked.Load().(map[string]struct{})
	_, blocked := blockedMap[token]

	if blocked {
		m.logger.Info("Token is in the blocklist", zap.String("token", token))
		return true
	}

	return false
}

func (m *TokenIsBlocked) loadBlocklist() error {
	file, err := os.Open(m.BlocklistFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	newMap := make(map[string]struct{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			newMap[line] = struct{}{}
		}
	}

	// Atomically store the new map
	m.blocked.Store(newMap)

	m.logger.Info("Blocklist reloaded",
		zap.String("file", m.BlocklistFile),
		zap.Int("entries", len(newMap)),
	)
	return nil
}

func (m *TokenIsBlocked) watchDirectoryLoop() {
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			// Check if the event is for the blocklist file
			if filepath.Clean(event.Name) != filepath.Clean(m.BlocklistFile) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				m.logger.Debug("Detected blocklist file change", zap.String("event", event.Op.String()))
				if err := m.loadBlocklist(); err != nil {
					m.logger.Warn("Failed to reload blocklist", zap.Error(err))
				}
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("Watcher error", zap.Error(err))
		}
	}
}

// Interface guards
var (
	_ caddy.Module             = (*TokenIsBlocked)(nil)
	_ caddy.Provisioner        = (*TokenIsBlocked)(nil)
	_ caddy.CleanerUpper       = (*TokenIsBlocked)(nil)
	_ caddyhttp.RequestMatcher = (*TokenIsBlocked)(nil)
)
