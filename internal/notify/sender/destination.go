// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package sender

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/notify"
)

// Errors returned for destinations. Their text never contains the URL or the
// secret.
var (
	ErrInvalidDestination = errors.New("sender: invalid notifier destination")
	ErrSecretUnavailable  = errors.New("sender: notifier secret unavailable")
)

const (
	envPrefix  = "env://"
	filePrefix = "file://"
	// maxSecretFileLen bounds the size of a secret file.
	maxSecretFileLen = 4096
)

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envNamRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// Destination is one notifier destination as written in the controller
// configuration. SecretRef is a reference (env://NAME or file:///abs/path),
// never the secret itself. The formatting methods never print the URL or the
// reference.
type Destination struct {
	Name      string
	Type      string
	URL       string
	SecretRef string
}

func (Destination) String() string   { return "sender.Destination{redacted}" }
func (Destination) GoString() string { return "sender.Destination{redacted}" }
func (d Destination) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, d.String())
}

func invalid(name, why string) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidDestination, name, why)
}

// Validate checks the destination syntax without reading any secret. It
// fails closed on unknown types, non-https URLs, URLs with userinfo, inline
// secrets and malformed secret references.
func (d Destination) Validate() error {
	if !nameRe.MatchString(d.Name) {
		return fmt.Errorf("%w: name must match %s", ErrInvalidDestination, nameRe)
	}
	switch d.Type {
	case TypeWebhook, TypeSlack, TypeTeams:
	default:
		return invalid(d.Name, "unknown type")
	}
	u, err := url.Parse(d.URL)
	switch {
	case err != nil || u.Host == "" || u.Hostname() == "":
		return invalid(d.Name, "url is not a valid absolute url")
	case u.Scheme != "https":
		return invalid(d.Name, "url must use https")
	case u.User != nil:
		return invalid(d.Name, "url must not contain userinfo")
	}
	switch {
	case strings.HasPrefix(d.SecretRef, envPrefix):
		if !envNamRe.MatchString(strings.TrimPrefix(d.SecretRef, envPrefix)) {
			return invalid(d.Name, "secret env reference is malformed")
		}
	case strings.HasPrefix(d.SecretRef, filePrefix):
		if p := strings.TrimPrefix(d.SecretRef, filePrefix); !filepath.IsAbs(p) {
			return invalid(d.Name, "secret file reference must be an absolute path")
		}
	default:
		return invalid(d.Name, "secret must be an env:// or file:// reference, inline secrets are not allowed")
	}
	return nil
}

// SecretResolver resolves a secret reference to its bytes.
type SecretResolver func(ref string) ([]byte, error)

// DefaultSecretResolver reads env://NAME from the environment and
// file:///abs/path from disk (at most maxSecretFileLen bytes, one trailing
// newline trimmed). Errors never contain the reference or the value.
func DefaultSecretResolver(ref string) ([]byte, error) {
	switch {
	case strings.HasPrefix(ref, envPrefix):
		v := os.Getenv(strings.TrimPrefix(ref, envPrefix))
		if v == "" {
			return nil, ErrSecretUnavailable
		}
		return []byte(v), nil
	case strings.HasPrefix(ref, filePrefix):
		f, err := os.Open(strings.TrimPrefix(ref, filePrefix))
		if err != nil {
			return nil, ErrSecretUnavailable
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxSecretFileLen+1))
		if err != nil || len(b) > maxSecretFileLen {
			return nil, ErrSecretUnavailable
		}
		return []byte(strings.TrimSuffix(string(b), "\n")), nil
	}
	return nil, ErrSecretUnavailable
}

// BuildFanOut validates every destination, resolves its secret and returns a
// FanOut over the matching senders. Any failure fails the whole build (fail
// closed); errors name the destination but never carry its URL or secret.
// resolve nil selects DefaultSecretResolver. An empty list returns nil, nil.
func BuildFanOut(dests []Destination, deps Deps, timeout time.Duration, resolve SecretResolver) (*notify.FanOut, error) {
	if len(dests) == 0 {
		return nil, nil
	}
	if resolve == nil {
		resolve = DefaultSecretResolver
	}
	seen := map[string]bool{}
	var ns []notify.Notifier
	for _, d := range dests {
		if err := d.Validate(); err != nil {
			return nil, err
		}
		if seen[d.Name] {
			return nil, invalid(d.Name, "duplicate name")
		}
		seen[d.Name] = true
		secret, err := resolve(d.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("%w for destination %q", ErrSecretUnavailable, d.Name)
		}
		if len(secret) < notify.MinSecretLen {
			return nil, invalid(d.Name, fmt.Sprintf("secret is shorter than %d bytes", notify.MinSecretLen))
		}
		n, err := NewSenderFromConfig(SenderConfig{Type: d.Type, URL: d.URL, Secret: secret}, deps)
		if err != nil {
			return nil, invalid(d.Name, "sender configuration rejected")
		}
		ns = append(ns, n)
	}
	return notify.NewFanOut(timeout, ns...)
}
