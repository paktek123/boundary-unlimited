// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package hostkey generates the per-session ephemeral host key presented by
// the worker's client-facing SSH server. It is not wired to any session flow.
package hostkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"golang.org/x/crypto/ssh"
)

const redacted = "[REDACTED]"

// PrivateKey wraps an ed25519 private key and never reveals it through
// formatting, JSON encoding or error strings.
type PrivateKey struct {
	key ed25519.PrivateKey
}

// String implements fmt.Stringer.
func (PrivateKey) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (PrivateKey) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb is redacted.
func (PrivateKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON implements json.Marshaler.
func (PrivateKey) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// MarshalText implements encoding.TextMarshaler.
func (PrivateKey) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Key is a freshly generated host keypair.
type Key struct {
	// Private is the redacting private key wrapper.
	Private PrivateKey
	// Signer signs with the private key.
	Signer ssh.Signer
	// AuthorizedKey is the public key in authorized_keys format without a
	// trailing newline.
	AuthorizedKey string
	// Fingerprint is the SHA256 fingerprint of the public key.
	Fingerprint string
}

// Generate returns a new Ed25519 host key from crypto/rand. Every call returns
// a different key.
func Generate(ctx context.Context) (*Key, error) {
	const op = "hostkey.Generate"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return &Key{
		Private:       PrivateKey{key: priv},
		Signer:        signer,
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))),
		Fingerprint:   ssh.FingerprintSHA256(sp),
	}, nil
}
