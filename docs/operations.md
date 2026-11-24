# Operations

Run the `kolo-pin` binary and watch it. Bounds are in [limits.md](limits.md); the library API is in [guide.md](guide.md).

## Run a pinning peer

```sh
kolo-pin run -data /var/lib/kolo-pin -listen 0.0.0.0:7450 -max-bytes 100GB
kolo-pin id -data /var/lib/kolo-pin
```

`id` prints the pinning peer's public key in hex, which owners put in their
capabilities. The key is created in the data directory on first use
(`identity.key`, mode 0600) and kept across restarts. The data directory
must be private (mode 0700); it is created with that mode when missing.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-data` | `KOLO_PIN_DATA` | required | data directory: `identity.key` and `store/` |
| `-listen` | `KOLO_PIN_LISTEN` | `127.0.0.1:7450` | UDP address for kolo-secure connections; `0.0.0.0:7450` on a server |
| `-max-bytes` | `KOLO_PIN_MAX_BYTES` | `100GB` | most bytes stored for all owners together; `B`, `KB`, `MB`, `GB`, `TB`, `KiB`, `MiB`, `GiB`, `TiB` |
| `-owners` | `KOLO_PIN_OWNERS` | empty | comma-separated hex owner keys to accept; empty accepts any owner and logs a warning at start (see below). An owner taken off the list loses its capability and logs at the next start; its revoke notes are still accepted |
| `-max-owners` | `KOLO_PIN_MAX_OWNERS` | `100000` | most owner records an open peer keeps, one per owner key ever seen; a new owner past it is refused (`ErrOwnerLimit`). Ignored with `-owners` |
| `-max-open-bytes` | `KOLO_PIN_MAX_OPEN_BYTES` | `256MiB` | memory the open logs may take, counted as 128 bytes per log and 256 per entry; the least recently used idle logs are closed past it |
| `-max-conns` | `KOLO_PIN_MAX_CONNS` | `2016` | most connections at once, handshaking or open; at most what kolo-transport's default memory allows, which is 2016 |
| `-max-conns-per-ip` | `KOLO_PIN_MAX_CONNS_PER_IP` | `4` | most connections from one source address, at most `-max-conns`; raise it for owners behind one NAT |
| `-add-timeout` | `KOLO_PIN_ADD_TIMEOUT` | none | most time one add may spend, such as `10m`; past it the add is refused as busy and what was stored is kept |
| `-health` | `KOLO_PIN_HEALTH` | `127.0.0.1:7451` | TCP address of `GET /healthz`, or `off` |
| `-metrics` | `KOLO_PIN_METRICS` | `127.0.0.1:7452` | TCP address of `GET /metrics`, or `off` |
| `-log-format` | `KOLO_PIN_LOG_FORMAT` | `text` | `text` or `json`, on stderr |
| `-log-level` | `KOLO_PIN_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

A flag wins over its environment variable. Addresses are IPv4; IPv6 is
refused. `/healthz` answers `200 ok` while the peer runs. SIGINT or SIGTERM
stops it cleanly: open requests end, the store is closed, exit code 0. A
bad flag exits with 2, including a `-health` or `-metrics` value that is
not an IPv4 address and a port from 0 to 65535 (such as `999.1.1.1:7452`
or `127.0.0.1:99999`); a failure to start, such as a valid address whose
port is in use, exits with 1.

An open peer, started without `-owners`, accepts a capability from any key:
anyone who knows the peer's public key can sign their own and store data up
to `-max-bytes`, and their records fill `-max-owners`. It is meant for a
peer you use alone or inside a network you trust. At start it logs
`open peer: every owner key is accepted ...` at warn level; to serve known
people, list their keys in `-owners`.

At start the peer serves at once and then reads every stored log once, in the background and one at a time, to offer it to kolo-sync; the time follows the number of entries (about 20 to 25 µs for a small entry; see "Memory" in [limits.md](limits.md)).

Logs are slog events: `serving` (key, address, bytes used, limit, owner
records, open-log budget),
`pinned`, `refused` (with the reason), `done` (remove, revoke), `dropped`
(expired, revoked, not covered, owner not accepted; the owner's `kept` count
is the logs whose delete failed), `dropped after retry`, `stopped`, and the
warnings `delete failed, log kept` (once when a delete first fails; the
sweep tries again after `retry`, then after twice as long, up to 64 times
that) and `state write failed`. They hold public keys, log IDs and sizes,
and a peer's address only at `-log-level debug`; never a private key, seed or
entry key.

On a VPS, build with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build
-trimpath ./cmd/kolo-pin`, run it as an unprivileged user with
`-listen 0.0.0.0:7450`, and open UDP port 7450 in the firewall. Keep the
health and metrics ports on 127.0.0.1. With an open `-owners`, anyone can
fill the disk up to `-max-bytes` and the records up to `-max-owners` with new
keys; list your owners to keep the peer for them.

## Monitor a pinning peer

`GET /metrics` on `-metrics` (default `127.0.0.1:7452`, `off` to disable)
answers in the Prometheus text exposition format. It listens on loopback by
default and never on the public address unless you set one. To read it
from another machine, put it behind a reverse proxy with authentication
(or an SSH tunnel); the endpoint itself has none.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kolo_pin_bytes_used` | gauge | | bytes stored for all owners, keys and values |
| `kolo_pin_bytes_max` | gauge | | `-max-bytes` |
| `kolo_pin_disk_free_bytes` | gauge | | free bytes on the data directory's filesystem (Linux, macOS, Windows) |
| `kolo_pin_owners` | gauge | | owners with a capability in use or a held log |
| `kolo_pin_owner_records` | gauge | | owner records stored, including owners with nothing held |
| `kolo_pin_owner_records_max` | gauge | | `-max-owners`; 0 with `-owners` |
| `kolo_pin_logs` | gauge | | held logs, including logs whose delete failed |
| `kolo_pin_entries` | gauge | | entries of all held logs, including logs whose delete failed |
| `kolo_pin_requests_total` | counter | `op`: `add`, `remove`, `status`, `revoke`, `sync_pull` | requests answered; `sync_pull` counts the kolo-sync streams other peers open on a hosted log (a new reader opens two: header, then pull; `FetchHead` and `Fetch` open one each) |
| `kolo_pin_refused_total` | counter | `reason`: `bad_token`, `expired_token`, `replayed_token`, `revoked`, `quota_exceeded`, `disk_full`, `owner_limit`, `oversized_entry`, `bad_signature`, `bad_proof`, `other` | requests refused |
| `kolo_pin_delete_markers_applied_total` | counter | | owner delete markers applied, each dropping one ciphertext the peer held; an entry that arrives already deleted is not counted |
| `kolo_pin_bytes_received_total` | counter | | bytes of new entries (records and ciphertexts) pulled from owners |
| `kolo_pin_bytes_served_total` | counter | | bytes kolo-sync wrote to peers pulling hosted logs, every frame (answers, errors, busy refusals) included |
| `kolo_pin_active_connections` | gauge | | open kolo-secure connections |
| `kolo_pin_active_sync_streams` | gauge | | kolo-sync streams running now: those served to pulling peers plus the pulls from owners |
| `kolo_pin_active_pulls` | gauge | | of those, the pulls from owners that `Add` runs |
| `kolo_pin_sync_pull_duration_seconds` | histogram | | duration of the pulls `Add` runs |
| `kolo_pin_request_duration_seconds` | histogram | `op`: `add`, `remove`, `status`, `revoke` | duration of pin requests; kolo-sync streams (`sync_pull`) are not timed, since kolo-sync reports when they start but not when they end |
| `kolo_pin_build_info` | gauge | `version`, `go_version` | always 1 |
| `kolo_pin_uptime_seconds` | gauge | | seconds since the program started |

The binary also exports the standard `go_*` runtime and `process_*`
metrics (process metrics on Linux and Windows).

What the metrics reveal: totals for the whole peer (bytes, owners, logs,
entries, request and refusal counts by kind, durations) and the build.
What they never hold: owner keys, log IDs, peer keys, IP addresses or any
per-owner number. Labels take only the fixed values in the table.
`kolo_pin_refused_total` does tell an observer how often, and why,
requests are refused.

A library user passes a `prometheus.Registerer` in `Options.Metrics` and
serves it as they like.
