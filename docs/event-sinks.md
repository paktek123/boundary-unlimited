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

## Planned configuration rules (from the security decision on #55)

These are requirements for the wiring slice, not current behaviour:

- the syslog default network is `tls`; `tcp` and `udp` need an explicit
  `insecure_plaintext = true`;
- client key material and CA bundles are `file://` references only, tokens are
  `env://` or `file://` references only, never inline;
- delivery is best-effort and must not block or fail the request path;
- until the wiring and its tests merge, the sink types stay rejected
  (enforcement-first).
