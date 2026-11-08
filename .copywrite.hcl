schema_version = 1

project {
  license        = "BUSL-1.1"
  copyright_year = 2024
  ignore_year1 = true # required to preserve existing start years

  header_ignore = [
    ".github/**",
    ".golangci.yml",
    ".release/linux/**",
    "enos/.enos/**",
    "internal/ui/.tmp/**",
    "website/.eslintrc.js",
    "website/prettier.config.js",
    "**/*_ent.*",
    "**/*_ent_test.*",

    # licensed under MPL - ignoring for now until the copywrite tool can support
    # multiple licenses per repo.
    "api/**",
    "sdk/**",
    "internal/proto/plugin/**",
    "internal/proto/controller/custom_options/**", 
    "internal/proto/controller/api/**",
    "internal/proto/worker/proxy/v1/**",

    # written for Boundary Unlimited and licensed under MIT (see NOTICE.md);
    # copywrite would otherwise rewrite these headers to the upstream license.
    "internal/accessrequest/**",
    "internal/runbook/**",
    "internal/masking/**",
    "internal/guardrails/**",
    "internal/notify/**",
    "internal/event/syslogfmt/**",
    "internal/event/sinkqueue/**",
    "internal/daemon/worker/recording/finalize/**",
    "internal/daemon/worker/recording/scratch/**",
    "internal/daemon/worker/recording/upload/**",
    "internal/daemon/worker/recording/bsrfs/**",
    "internal/daemon/worker/proxy/ssh/**",
    "internal/daemon/worker/proxy/kube/**",
    "internal/bsr/playback/**",
    "internal/bsr/ssh/recorder/**",
    "internal/cmd/commands/connect/kube_credentials.go",
    "internal/cmd/commands/connect/kube_credentials_test.go",
    "internal/cmd/commands/connect/kubeconfig.go",
    "internal/cmd/commands/connect/kubeconfig_test.go",
    "internal/cmd/commands/connect/kubecreds/**",
    "internal/cmd/commands/connect/ssh_known_hosts.go",
    "internal/cmd/commands/connect/ssh_known_hosts_test.go",
    "internal/cmd/commands/connect/ssh_pinned.go",
    "internal/cmd/commands/connect/ssh_pinned_test.go",
  ]
}
