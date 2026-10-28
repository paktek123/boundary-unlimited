// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostkey

import (
	"bytes"
	"context"
	"crypto/rsa"
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/target/ssh/hostkeypolicy"
	"golang.org/x/crypto/ssh"
)

// Typed validation errors. Validate and New wrap exactly one of them so the
// API layer can map a failure with errors.Is. Messages never contain key
// bytes, at most a SHA256 fingerprint.
var (
	// ErrEmptyPolicy: no pinned keys and no CAs.
	ErrEmptyPolicy = stderrors.New("host key policy has no pinned keys or host CAs")
	// ErrTooManyEntries: more than hostkeypolicy.MaxHostKeys entries in total.
	ErrTooManyEntries = stderrors.New("host key policy has too many entries")
	// ErrEntryTooLarge: an entry is larger than hostkeypolicy.MaxEntryLength.
	ErrEntryTooLarge = stderrors.New("host key policy entry is too large")
	// ErrMalformedEntry: an entry is empty, unparsable or holds more than one key.
	ErrMalformedEntry = stderrors.New("host key policy entry is malformed")
	// ErrKeyOptions: an entry carries authorized_keys options.
	ErrKeyOptions = stderrors.New("host key policy entry has key options")
	// ErrInvalidComment: an entry's comment contains control characters.
	ErrInvalidComment = stderrors.New("host key policy entry has an invalid comment")
	// ErrDuplicateKey: the same key appears more than once.
	ErrDuplicateKey = stderrors.New("host key policy has a duplicate key")
	// ErrWildcardPattern: an entry looks like a wildcard host pattern.
	ErrWildcardPattern = stderrors.New("host key policy entry has a wildcard host pattern")
	// ErrWeakKey: a DSA key or an RSA key smaller than hostkeypolicy.MinRSABits.
	ErrWeakKey = stderrors.New("host key policy key is too weak")
	// ErrUnsupportedAlgorithm: a key type other than ed25519, ECDSA or RSA.
	ErrUnsupportedAlgorithm = stderrors.New("host key policy key algorithm is not supported")
	// ErrCertificateEntry: a pinned key or a CA entry is a certificate.
	ErrCertificateEntry = stderrors.New("host key policy entry is a certificate")
)

// Validate checks p against the upstream host key rules: at least one entry,
// at most hostkeypolicy.MaxHostKeys entries in total, each at most
// hostkeypolicy.MaxEntryLength bytes, authorized_keys format with no options,
// a comment without control characters, no wildcard patterns, no duplicate
// keys (compared by their marshalled bytes, across pinned keys and CAs), only
// ed25519, ECDSA P-256/384/521 and RSA of at least hostkeypolicy.MinRSABits
// bits, and no certificates. The returned error wraps one of the Err*
// values above.
func Validate(p Policy) error {
	_, _, err := validate(p)
	return err
}

// validate returns the parsed pinned keys and CAs of a valid policy.
func validate(p Policy) (pinned, cas []ssh.PublicKey, _ error) {
	const op = "hostkey.Validate"
	ctx := context.Background()
	fail := func(class error, format string, args ...any) error {
		return errors.Wrap(ctx, fmt.Errorf("%w: %s", class, fmt.Sprintf(format, args...)), op, errors.WithCode(errors.InvalidParameter))
	}
	total := len(p.PinnedKeys) + len(p.HostCAs)
	if total == 0 {
		return nil, nil, fail(ErrEmptyPolicy, "configure at least one pinned key or host CA")
	}
	if total > hostkeypolicy.MaxHostKeys {
		return nil, nil, fail(ErrTooManyEntries, "%d entries (max %d)", total, hostkeypolicy.MaxHostKeys)
	}
	seen := make(map[string]struct{}, total)
	check := func(kind string, i int, entry string) (ssh.PublicKey, error) {
		k, detail, class := parseEntry(entry)
		if class != nil {
			return nil, fail(class, "%s %d: %s", kind, i, detail)
		}
		if _, ok := k.(*ssh.Certificate); ok {
			return nil, fail(ErrCertificateEntry, "%s %d: certificates are not accepted, pin the public key or the CA", kind, i)
		}
		fp := ssh.FingerprintSHA256(k)
		if detail, class := checkAlgorithm(k, fp); class != nil {
			return nil, fail(class, "%s %d: %s", kind, i, detail)
		}
		mk := string(k.Marshal())
		if _, dup := seen[mk]; dup {
			return nil, fail(ErrDuplicateKey, "%s %d: %s", kind, i, fp)
		}
		seen[mk] = struct{}{}
		return k, nil
	}
	for i, s := range p.PinnedKeys {
		k, err := check("pinned key", i, s)
		if err != nil {
			return nil, nil, err
		}
		pinned = append(pinned, k)
	}
	for i, s := range p.HostCAs {
		k, err := check("host CA", i, s)
		if err != nil {
			return nil, nil, err
		}
		cas = append(cas, k)
	}
	return pinned, cas, nil
}

// parseEntry parses one authorized_keys entry. On failure it returns the
// error class and a message that holds no key material.
func parseEntry(entry string) (ssh.PublicKey, string, error) {
	if len(entry) > hostkeypolicy.MaxEntryLength {
		return nil, fmt.Sprintf("exceeds %d bytes", hostkeypolicy.MaxEntryLength), ErrEntryTooLarge
	}
	if strings.TrimSpace(entry) == "" {
		return nil, "entry is empty", ErrMalformedEntry
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(entry))
	if err != nil {
		if strings.ContainsAny(entry, "*?") {
			return nil, "host patterns are not accepted", ErrWildcardPattern
		}
		return nil, "not a valid public key", ErrMalformedEntry
	}
	for _, o := range options {
		if strings.ContainsAny(o, "*?") {
			return nil, "host patterns are not accepted", ErrWildcardPattern
		}
	}
	if len(options) > 0 {
		return nil, "key options are not allowed", ErrKeyOptions
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, "entry must contain exactly one key", ErrMalformedEntry
	}
	for _, r := range strings.TrimSpace(entry) {
		if r < 0x20 || r == 0x7f {
			return nil, "control characters are not allowed", ErrInvalidComment
		}
	}
	for _, r := range comment {
		if r < 0x20 || r == 0x7f {
			return nil, "control characters are not allowed", ErrInvalidComment
		}
	}
	if strings.ContainsAny(comment, "*?") {
		return nil, "host patterns are not accepted", ErrWildcardPattern
	}
	return pub, "", nil
}

// checkAlgorithm vets the key type and strength. Certificates are checked by
// the caller before this is reached.
func checkAlgorithm(k ssh.PublicKey, fp string) (string, error) {
	switch k.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return "", nil
	case "ssh-dss":
		return fmt.Sprintf("DSA key %s is not accepted", fp), ErrWeakKey
	case ssh.KeyAlgoRSA:
		cpk, ok := k.(ssh.CryptoPublicKey)
		if !ok {
			return fmt.Sprintf("key %s", fp), ErrUnsupportedAlgorithm
		}
		rpk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rpk.N.BitLen() < hostkeypolicy.MinRSABits {
			return fmt.Sprintf("RSA key %s is smaller than %d bits", fp, hostkeypolicy.MinRSABits), ErrWeakKey
		}
		return "", nil
	default:
		return fmt.Sprintf("key type %q for key %s", k.Type(), fp), ErrUnsupportedAlgorithm
	}
}
