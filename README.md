# WireGuard Proxy Management Gateway

This service provides an HTTP API that creates and manages WireGuard peers on demand. It enforces IPv4-only access, renders JSON responses from a template, and performs background garbage collection of stale peers.

## Features

- `POST /peer`: create a peer for the caller's IPv4 address, rendering the response from a JSON template.
- `DELETE /peer/:id`: remove a peer by its identifier.
- `GET /healthz`: health probe endpoint.
- Optional bearer token authentication for mutating endpoints.
- IPv6 requests are rejected with HTTP 403.
- Peers are garbage-collected if they never connect within 10 minutes or have not handshaked for 24 hours.
- Template reload endpoint: `POST /admin/reload-template` (requires auth if configured).

## Configuration

Environment variables (defaults in parentheses):

| Variable | Description |
| --- | --- |
| `LISTEN_ADDR` (`:8080`) | HTTP listen address. |
| `WG_INTERFACE` | WireGuard interface name (required). |
| `WG_ENDPOINT` | Public endpoint for the WireGuard server (required). |
| `PERSISTENT_KEEPALIVE_SECONDS` (`0`) | Persistent keepalive interval (0 disables). |
| `JSON_TEMPLATE_PATH` | Path to the JSON response template (required). |
| `AUTH_BEARER_TOKEN` | Optional bearer token required for POST/DELETE endpoints if set. |
| `TRUST_PROXY_LOOPBACK_ONLY` (`true`) | When true, trust `X-Forwarded-For` only from loopback proxies. |
| `USE_PRESHARED_KEY` (`false`) | Generate a preshared key for peers when true. |

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
export WG_INTERFACE=wg0
export WG_ENDPOINT=vpn.example.com:51820
export JSON_TEMPLATE_PATH=./templates/peer_response.json.tmpl

curl -X POST http://127.0.0.1:8080/peer
```

