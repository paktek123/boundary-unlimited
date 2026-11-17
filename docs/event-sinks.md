# SIEM event sink transports (library only, not yet configurable)

Refs #54, #55, #56.

Two transport libraries exist for streaming audit events to a SIEM. **Neither
can be enabled by configuration yet**: the event system has no `http` or
`syslog` sink type and the controller config parser accepts no option for them.
A configuration naming such a sink fails validation as an unknown sink type, so
nothing can silently send (or silently not send) audit data. The delivery
wiring lands in a later slice; this page documents what the libraries enforce so
that slice and operators can rely on it.

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

## Configuration rules (validated, but the sinks are still refused)

`event.SinkConfig` now parses `type = "http"` / `type = "syslog"` with an
`http { ... }` or `syslog { ... }` block and validates it strictly, then
refuses it with "not yet supported" because nothing delivers events yet:

- `http`: `url` (https only, no userinfo), `token` as `env://NAME` or an
  absolute `file://` reference (inline tokens are refused), `format` of `hec`
  or `json`;
- `syslog`: `address` as `host:port`; `network` defaults to `tls`; `tcp` and
  `udp` need `insecure_plaintext = true`; `ca_file`, `client_cert_file` and
  `client_key_file` are absolute `file://` references and only valid with `tls`;
- both: `allow_private_cidrs` is the explicit per-sink allow-list for private
  destinations (default empty; `0.0.0.0/0` and `::/0` are refused),
  `delivery_guarantee = enforced` is refused, unknown keys such as
  `skip_verify` fail the load, and errors never contain the URL, address or
  secret reference.

Remaining before a network sink can be turned on: hooking the pipeline into the
eventer, failing startup on an unresolvable secret, and the rate-limited
counts-only system event for drops. Until that merges the sink types stay
rejected (enforcement-first).
