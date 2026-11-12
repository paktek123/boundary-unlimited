# `policy_engine` controller configuration

Selects the external authorizer consulted by `AuthorizeSession` after the
built-in grants allowed a request (see `docs/rfc/external-authorizer.md`). The
final decision is the AND of the grants and the authorizer: it can deny, never
grant.

```hcl
policy_engine {
  authorizer_id = "opa"                 # labels audit events
  url           = "https://pdp.example.com/v1/authorize"
  secret        = "env://PDP_SECRET"    # or file:///abs/path; bearer token, >= 16 bytes
  timeout       = "2s"                  # optional, max 5s
  cache_ttl     = "0s"                  # optional DENY-only cache, max 5s
}
```

Fail closed: the controller refuses to start when the block is invalid, the
secret cannot be resolved or is too short, or the hook cannot be built. At
request time every error, timeout or invalid response denies the request and
the client only sees a generic forbidden error. There is no `fail_open`,
`skip_verify` or TLS option (unknown keys are rejected); TLS 1.2 is the minimum,
redirects and proxies are not followed, and the authorizer host is dialled
through the netguard dialer (loopback, private, link-local and metadata
addresses are refused).

Each decision writes an audit event with operation
`authorize-session/<allow|deny>/<reason>`; no request or response bodies, URLs
or secrets are included.
