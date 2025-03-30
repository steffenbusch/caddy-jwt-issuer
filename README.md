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
            sign_key {$JWT_SIGN_KEY}
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
     "comment": "Password is Tschigerillo"
   },
   "alice": {
     "password": "$2a$14$d3PG6.orP1Q.0nJ5aLGcEeGui2Zc5TPcq4maq/OjQ2khAeVi4YNTa",
     "audience": [
       "api-endpoint-1",
       "admin-endpoint"
     ],
     "comment": "For security, do not use plaintext passwords in comments as demonstrated above."
   }
}
```

To generate a bcrypt password hash, you can use the `caddy` command itself:

```bash
caddy hash-password
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
