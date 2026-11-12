# `notifier` controller configuration

Destinations for approval notifications (Slack, Teams, generic webhook). One
labelled block per destination:

```hcl
notifier "ops-slack" {
  type   = "slack"                    # webhook | slack | teams
  url    = "https://hooks.slack.com/services/..."
  secret = "env://NOTIFY_SECRET"      # or file:///abs/path; inline secrets are rejected
}
```

The controller refuses to start (error text never contains the URL or secret) when:

- the URL is not https or contains userinfo;
- `secret` is not an `env://NAME` or absolute `file://` reference;
- the type is unknown, the name is duplicated, or a block has any other key
  (there is deliberately no `skip_verify` or TLS option);
- the resolved secret is shorter than 16 bytes or cannot be read.

Senders use the guarded dialer: destinations resolving to loopback, private,
link-local or metadata addresses are refused at dial time.

Status: **currently rejected at load.** The stanza is parsed and validated
(`sender.BuildFanOut`), but the controller does not yet hand the fan-out to the
access-request service, so `Parse` fails with "notifier: not yet supported"
rather than accept a setting that would send nothing. The guard is lifted in
the change that wires the fan-out into the service (#262).
