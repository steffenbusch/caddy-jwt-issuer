# caddy-jwt-issuer

The **caddy-jwt-issuer** plugin for [Caddy](https://caddyserver.com) issues JSON Web Tokens (JWT) after username and password authentication.
It is intended to generate JWTs that are checked with <https://github.com/ggicci/caddy-jwt>, which provides the JWT Authentication.

[![Go Report Card](https://goreportcard.com/badge/github.com/steffenbusch/caddy-jwt-issuer)](https://goreportcard.com/report/github.com/steffenbusch/caddy-jwt-issuer)

## Features

This plugin provides the following features:

- **JWT Issuance**: Issues JWTs after successful username and password authentication. The issued JWT will include the Audience elements retrieved from the users database.
- **Configurable Token Lifetime**: Allows setting the default lifetime of the issued JWTs. Each user can have their own individual token lifetime configured in the user database. If not, the default token lifetime from the plugin configuration is used.
- **User Database**: Supports loading user credentials from a specified JSON file.
- **HS256 Signing**: Generates JWTs with the symmetric signing algorithm HS256.
- **Structured Logging**: Provides detailed logging for authentication attempts and token issuance. The emitted logs can be used with `fail2ban` or similar tools to block repeated failed attempts.
- **Customizable Cookies**: Allows setting custom cookie names and domains for issued JWTs.

## Building

To build Caddy with this module, use [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
$ xcaddy build --with github.com/steffenbusch/caddy-jwt-issuer
```

## Caddyfile Config

To use the caddy-jwt-issuer plugin, add the following directive to your Caddyfile:

```caddyfile
:8080 {
    handle /login {
        jwt_issuer {
            sign_key <base64-encoded-sign-key>
            user_db_path <path-to-user-db>
            token_issuer <issuer-name>
            default_token_lifetime <duration>
            enable_cookie
            cookie_name <cookie-name>
            cookie_domain <cookie-domain>
        }
    }
}
```

### Configuration Options

- `sign_key`: The base64-encoded secret key used to sign the JWTs.
  - *Usage Tip*: To create a secure base64-encoded sign key, you can use the command `openssl rand -base64 32`. This command generates a random 32-byte key and encodes it in base64 format.
  - *Placeholder Support*: You can also use a placeholder to reference a file containing the key, such as `{file./path/to/jwt-secret.txt}`. The file's content will be read and used as the signing key.
- `user_db_path`: The path to the user database JSON file containing username, password, audience information, and optional deviating token lifetime. See the [example](#sample-usersjson) at the end of this README.
- `token_issuer`: The issuer name to be included in the JWTs.
- `default_token_lifetime`: The lifetime of the issued JWTs (e.g., "1h" for 1 hour). If not configured, the default value is 15 minutes.
- `enable_cookie`: If this option is present, the plugin will set a cookie in the HTTP response containing the issued JWT.
- `cookie_name`: The name of the cookie used to store the JWT. Defaults to `jwt_auth` if not specified.
- `cookie_domain`: The domain for which the cookie is valid. For example, `.example.com` makes the cookie valid for all subdomains of `example.com`.

### Example: Protecting an API Endpoint

The following example demonstrates how to protect an API endpoint using the caddy-jwt-issuer plugin:

```caddyfile
:8080 {
    handle /login {
        jwt_issuer {
            sign_key {file./path/to/jwt-secret.txt}
            user_db_path /path/to/user_db.json
            token_issuer https://jwt.example.com
            default_token_lifetime 30m
        }
    }

    route /api/* {
        # See https://github.com/ggicci/caddy-jwt
        jwtauth {
            sign_key {file./path/to/jwt-secret.txt}
            sign_alg HS256
            issuer_whitelist https://jwt.example.com
            audience_whitelist "api-endpoint-1"
            user_claims sub
        }

        respond "Protected API endpoint."
    }
}
```

In this example, the `/api/*` endpoint is protected by JWT authentication. Only requests with valid JWTs containing the specified audience will be allowed.

### Sample `users.json`

Here is a sample `users.json` file that can be used with the caddy-jwt-issuer plugin:

```json
{
   "bob": {
     "password": "$2a$14$SL41zi5LqFYnjIs/U0lX4ewZsrr8aipeCDivi02ccgwdhb/9LahxG",
     "audience": [
       "api-endpoint-1"
     ],
     "token_lifetime": "1h",
     "meta_claims": {
       "name": "Bob Example",
       "app1": true,
       "app2": false,
       "app3": true
     },
     "comment": "Password is Tschigerillo"
   },
   "alice": {
     "password": "$2a$14$d3PG6.orP1Q.0nJ5aLGcEeGui2Zc5TPcq4maq/OjQ2khAeVi4YNTa",
     "audience": [
       "api-endpoint-1",
       "admin-endpoint"
     ],
     "token_valid_until": "tomorrow at 4:00 am",
     "totp_secret": "JBSWY3DPEHPK3PXP",
     "meta_claims": {
       "name": "Alice Example",
       "app1": false,
       "app2": true,
       "app3": false
     },
     "comment": "For security, do not use plaintext passwords in comments as demonstrated above."
   }
}
```

This example demonstrates the following configuration options:

- `"password"`: The bcrypt hash of the user's password.
- `"audience"`: A list of audiences the user has access to.
- `"token_lifetime"` (optional): Specifies the lifetime of the token for this user (e.g., "1h"). If present, it will override the `default_token_lifetime` configured for the plugin.
- `"token_valid_until"` (optional): A specific expiration time for the token (e.g., "tomorrow at 4:00 am"). If present, it will override both the `"token_lifetime"` for the user and the `default_token_lifetime` configured for the plugin. This field supports natural language date/time parsing using [when](https://github.com/olebedev/when). For more information, refer to the [when documentation](https://github.com/olebedev/when).
- `"totp_secret"` (optional): Specifies the TOTP secret for enabling two-factor authentication (2FA). If provided, the user will be required to enter a time-based one-time password (TOTP) during login. To set up the secret in a 2FA app, you can use a tool like [https://stefansundin.github.io/2fa-qr/](https://stefansundin.github.io/2fa-qr/).
- `"meta_claims"` (optional): Additional claims to include in the token, such as:
  - `"name"`: The user's full name.

Placeholder Support: Values in `meta_claims` can include placeholders, which will be dynamically replaced at the time of JWT issuance. For example, a placeholder like `{http.vars.client_ip}` will be replaced with the IP Address of the client.

By default, the issued JWT includes an `ip` claim representing the client's IP address. Additional predefined claims are as follows: `sub` (username), `iss` (value from `token_issuer`), `aud` (an array of audiences), `jti` (a unique identifier), `iat` (issued-at timestamp), `nbf` (not-before timestamp), and `exp` (expiration timestamp). These predefined claims are immutable and cannot be overridden by custom meta claims.

These `meta_claims` can be very useful when used with the `jwtauth` directive of the [caddy-jwt](https://github.com/ggicci/caddy-jwt) plugin, as this Caddy plugin can provide such meta claims as placeholders. These placeholders can then be utilized in various contexts, such as rendering dynamic content in HTML templates. For more details about how `meta_claims` are handled in the `jwtauth` plugin, refer to the [source code explanation](https://github.com/ggicci/caddy-jwt/blob/main/jwt.go#L121).

To generate a bcrypt password hash, you can use the `caddy` command itself:

```bash
caddy hash-password
```

To create a secure, random key in the correct format for the `totp_secret`, you can use the following command:

```bash
openssl rand 30 | base32 | tr --delete '='
```

If you need to update user information such as adding a new user, updating a password hash, or changing the audience, you can modify the users database file accordingly. After making the changes, reload the Caddy configuration with `--force` to apply the updates.

### Example: Obtaining a JWT

You can obtain a JWT by sending a POST request to the configured endpoint such as `localhost:8080/login` (due to `handle /login` in the `Caddyfile`)
with `Content-Type` of `application/json` and the POST data of the credentials. Here is an example using `curl`:

```bash
curl http://localhost:8080/login \
     -H "Content-Type: application/json" \
     -d '{"username": "bob", "password": "Tschigerillo"}'
{"message":"Success","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXBpLWVuZHBvaW50LTEiXSwiZXhwIjoxNzM5MTEzODcyLCJpYXQiOjE3MzkxMTAyNzIsImlzcyI6Imh0dHBzOi8vand0LmV4YW1wbGUuY29tIiwianRpIjoiNzMyZjk0ZGEtYTQyYS00MDJkLTgzNzctMjYwY2MzYzRjN2ZlIiwibmJmIjoxNzM5MTEwMjcyLCJzdWIiOiJib2IifQ._FRER6YwUTSUXXyfpEvgb_1NRejfBQT_EIFDBGUMEx4"}
```

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Caddy](https://caddyserver.com) for providing a powerful and extensible web server.
- [caddy-jwt](https://github.com/ggicci/caddy-jwt) for `jwtauth`, which provides the JWT Authentication.
- [when](https://github.com/olebedev/when/) for natural language date/time parsing used in `token_valid_until`.
- [otp](https://github.com/pquerna/otp/) for TOTP used to validate the 2FA codes.
