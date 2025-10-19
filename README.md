# WireGuard Proxy Management Gateway

This service provides an HTTP API that creates and manages WireGuard peers on demand. It enforces IPv4-only access, renders JSON responses from a template, and performs background garbage collection of stale peers.

## Features

- `POST /peer`: create a peer for the caller's IPv4 address, rendering the response from a JSON template.
- `DELETE /peer/:id`: remove a peer by its identifier.
- `GET /healthz`: health probe endpoint.
- JWT authentication for peer creation and HTTP basic auth for administrative endpoints.
- IPv6 requests are rejected with HTTP 403.
- Peers are garbage-collected if they never connect within 10 minutes or have not handshaked for 24 hours.
- Template reload endpoint: `POST /admin/reload-template` (requires auth if configured).

## Configuration

The gateway is configured through a JSON file. Use the `--config` flag to point the server to a configuration file (defaults to `config.json`).

```json
{
  "listen_addr": ":8080",
  "wg_interface": "wg0",
  "wg_endpoint": "vpn.example.com:51820",
  "persistent_keepalive_seconds": 0,
  "json_template_path": "./templates/peer_response.json.tmpl",
  "trust_proxy_loopback_only": true,
  "log_level": "info",
  "use_preshared_key": false,
  "auth": {
    "basic": {
      "username": "admin",
      "password": "changeme"
    },
    "jwt": {
      "secret": "replace-with-strong-secret"
    }
  }
}
```

### Authentication

- `POST /peer` requires a JWT signed with the configured secret using the HS256 algorithm and provided via the `Authorization: Bearer <token>` header.
- `GET /healthz`, `DELETE /peer/:id`, and `POST /admin/reload-template` require HTTP basic authentication using the configured credentials.

## Running

Install dependencies and run the gateway:

```bash
make tidy
make run
```

The service requires access to a WireGuard interface. Ensure the interface exists and the executing user has permission to configure it.

## Testing

```bash
make test
```

## Template

A sample template is provided at `templates/peer_response.json.tmpl`. Customize it to match the desired response schema. The template is loaded at startup and can be reloaded via `POST /admin/reload-template`.

## Example

```bash
curl -H "Authorization: Bearer <jwt>" -X POST http://127.0.0.1:8080/peer
```

