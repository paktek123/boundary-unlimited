# SIEM event sink transports (http and syslog)

Refs #54, #55, #56.

Two transport libraries stream audit events to a SIEM. The `http` and `syslog`
sink types are delivered: the config parser validates them strictly,
`event.NewEventer` builds the bounded, best-effort pipeline of `internal/event/netsink` through the
registered network sink factory (linked into `cmd/boundary`), and
`Eventer.FlushNodes` drains the queues at shutdown. The wiring is fail closed:
if no factory is registered, or building a sink fails (for example the secret
reference cannot be resolved), the configuration is refused with
`event.ErrNetworkSinkNotSupported` or a startup error instead of silently
dropping audit data. This page documents what the libraries enforce.

Both implement `sinkqueue.Sender` and deliver best-effort batches. Errors never
contain entry contents, URLs, tokens or response bodies.

## `internal/event/httpsink` (Splunk HEC and generic JSON webhook)

| Property | Behaviour |
|---|---|
| Scheme | `https` only; no userinfo, fragment or opaque URL |
| TLS | minimum 1.2; no option to skip verification; system roots unless `RootCAs` is set |
| Redirects / proxy | never followed; no proxy from the environment |
| Dialing | `netguard.Dialer`: loopback, private, link-local and metadata addresses are refused unless explicitly allow-listed with `AllowedCIDRs` |
| Token | at least 8 printable ASCII bytes; never printed (`String`/`GoString` are redacted) |
| Timeout | default 10s, maximum 60s |
| Body | at most 8 MiB; the response read is bounded to 4 KiB |
| `hec` format | body is one `{"event":<entry>}` object per entry, `Authorization: Splunk <token>` |
| `json` format | body is a JSON array of the entries, `Authorization: Bearer <token>` |

## `internal/event/syslogsink` (RFC 5424 over UDP, TCP or TLS)

Entries are framed by `internal/event/syslogfmt`: a datagram for UDP, an
octet-counted frame for TCP and TLS.

| Property | Behaviour |
|---|---|
| Networks | `udp`, `tcp`, `tls` |
| Address | `host:port`, both required |
| TLS | minimum 1.2 and fixed; no option to skip verification; optional `RootCAs`, `ServerName` and client certificate (mutual TLS) |
| TLS options on `udp`/`tcp` | rejected as invalid configuration |
| Timeouts | dial and write default to 5s; negative values are invalid |

## Delivery semantics: best-effort only

Network sinks are **best-effort** and can never satisfy `delivery_guarantee =
enforced`; only the file sink keeps that guarantee. The queue in front of a
network sink (`internal/event/sinkqueue`) is bounded in entries and bytes:

- a best-effort producer is never blocked; when the queue is full the oldest
  entries are dropped and counted (`Dropped`), and a batch whose retries are
  exhausted is dropped and counted;
- an `enforced` queue instead returns `ErrQueueFull` and becomes permanently
  failed when retries are exhausted, so the caller can stop rather than lose
  audit events silently (this mode is not used for network sinks);
- `Close` returns an error wrapping `ErrDropped` when anything was ever lost.

## Configuration rules

`internal/event` parses `type = "http"` / `type = "syslog"` with an `http { ... }`
or `syslog { ... }` block and validates it strictly (`sink_network_config.go`).
Without a registered delivery factory a valid block is refused with "not yet
supported". The rules it applies (security decision on #55):

- `http`: `url` (https only, no userinfo), `token` as `env://NAME` or an
  absolute `file://` reference (inline tokens refused), `format` of `hec` or
  `json`;
- `syslog`: `address` as `host:port`; `network` defaults to `tls`; `tcp` and
  `udp` need `insecure_plaintext = true`; `ca_file`, `client_cert_file` and
  `client_key_file` are absolute `file://` references, valid only with `tls`;
- both: `allow_private_cidrs` is the explicit per-sink allow-list for private
  destinations (default empty; `0.0.0.0/0` and `::/0` refused),
  `delivery_guarantee = enforced` refused, unknown keys such as `skip_verify`
  fail the load, and errors never contain the URL, address or secret
  reference.

Delivery is best-effort: entries still queued when the process is killed
(rather than shut down normally) are lost. Still to come: the rate-limited
counts-only system event for drops.
