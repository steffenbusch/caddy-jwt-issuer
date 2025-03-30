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
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Initialize the module by registering it with Caddy
func init() {
	caddy.RegisterModule(JWTIssuer{})
	httpcaddyfile.RegisterHandlerDirective("jwt_issuer", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("jwt_issuer", "after", "basic_auth")
}

// parseCaddyfile parses the Caddyfile configuration
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m = new(JWTIssuer)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UnmarshalCaddyfile parses the configuration from the Caddyfile.
func (m *JWTIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {

		for d.NextBlock(0) {
			param := d.Val()
			var arg string
			if param == "enable_cookie" {
				m.EnableCookie = true
				continue
			}
			if !d.Args(&arg) {
				return d.ArgErr()
			}
			switch param {
			case "default_token_lifetime":
				duration, err := time.ParseDuration(arg)
				if err != nil {
					return fmt.Errorf("invalid default_token_lifetime duration: %s", err)
				}
				m.DefaultTokenLifetime = duration
			case "sign_key":
				m.SignKey = arg
			case "user_db_path":
				m.UserDBPath = arg
			case "token_issuer":
				m.TokenIssuer = arg
			case "cookie_name":
				m.CookieName = arg
			case "cookie_domain":
				m.CookieDomain = arg
			default:
				return d.Errf("unknown subdirective: %s", param)
			}
		}
	}

	return nil
}
