# Caddy JWT Issuer Example

This folder contains an example configuration for using the Caddy JWT Issuer plugin. The setup demonstrates how to protect multiple applications with JWT-based authentication and how to issue tokens using an interactive login endpoint. Users can log in through a browser form to obtain a JWT, which can then be used to access protected resources.

## Use Case

The example is designed for a scenario where:

- A central authentication service (`auth.example.com`) issues JWT tokens.
- Multiple applications (`app1.example.com` and `app2.example.com`) validate these tokens to protect their resources.
- Users are redirected to a login page if they are not authenticated.

## Files

### `Caddyfile`

The main configuration file for the Caddy server. It includes:

- **`auth.example.com`**:
  - Handles login and token issuance using the `jwt_issuer` directive.
  - Protects the `/portal.html` and `/logout.html` endpoint with JWT authentication.
  - Upon logout, the HTTP cookie is cleared, and the JWT's JTI is added to a blocklist file as specified by the `placeholder_dump` configuration.
    For more information about the `placeholder_dump` directive, visit its [GitHub repository](https://github.com/steffenbusch/caddy-placeholder-dump).
  - Redirects unauthenticated users to the login page.
- **`app1.example.com`** and **`app2.example.com`**:
  - Protect resources using JWT authentication.
  - Uses the `token_is_blocked` matcher to block requests with revoked tokens.
  - Redirect unauthenticated users to the central login page.

### `example-users.json`

A JSON file containing user credentials for the JWT issuer. This file is referenced in the `Caddyfile` under the `jwt_issuer` directive.

### `html/`

A folder containing static HTML files for the login, logout, and portal pages:

- `login.html`: The login page where users can authenticate.
- `logout.html`: A page to handle user logout and clear cookies.
- `portal.html`: A protected page that requires authentication.

## How to Use

1. **Prepare the Environment**:
   - Ensure Caddy is installed with the required plugins (`jwt_issuer`, `jwtauth`, and `extra-placeholders`).

2. **Update Configuration**:
   - Adjust placeholders in the `Caddyfile` (e.g., `{file./path/to/jwt-secret.txt}`) with actual values.
   - Configure the `blocklist_file` option in the `token_is_blocked` matcher to specify the path to the blocklist file.

3. **Start Caddy**:
   - Run the Caddy server using the provided `Caddyfile`.

4. **Access the Services**:
   - Visit `auth.example.com` to log in and obtain a JWT.
   - Access `app1.example.com` or `app2.example.com` with the issued JWT to use the protected resources.

## Notes

- The `jwt_issuer` directive is responsible for issuing tokens, while the `jwtauth` directive validates them.
- The `token_is_blocked` matcher ensures that revoked tokens are blocked by referencing a blocklist file.
- The `extra-placeholders` module is used to handle redirection with query parameters.
- Ensure the `example-users.json` file and the blocklist file are properly secured and not exposed publicly.

For more details, refer to the [Caddy documentation](https://caddyserver.com/docs/) and the plugin repositories.
