// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package injectauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// minRSABits is the smallest RSA modulus accepted for injected private keys.
const minRSABits = 2048

var (
	// ErrUsernameRequired is returned when no username is supplied.
	ErrUsernameRequired = errors.New("injectauth: username required")
	// ErrNoCredential is returned when neither a password nor a private key is
	// supplied.
	ErrNoCredential = errors.New("injectauth: no password or private key supplied")
	// ErrBadPrivateKey is returned when the private key cannot be used: it is
	// unparsable, encrypted without a (correct) passphrase, or too weak.
	ErrBadPrivateKey = errors.New("injectauth: unusable private key")
	// ErrBadCertificate is returned when the ssh certificate cannot be used: it
	// is unparsable, not a user certificate, outside its validity window,
	// supplied without a private key, or does not match the private key.
	ErrBadCertificate = errors.New("injectauth: unusable certificate")
)

// Input is the credential material for one upstream ssh connection.
type Input struct {
	Username   string
	Password   string
	PrivateKey []byte
	Passphrase []byte
	// Certificate is an optional signed ssh user certificate in authorized-key
	// format. It requires PrivateKey and must certify that key.
	Certificate []byte
}

// now is the clock used to check certificate validity; tests may replace it.
var now = time.Now

// AuthMethods returns the username and ssh auth methods for in. If both a
// private key and a password are supplied, both methods are returned with the
// key first; neither is silently dropped.
func AuthMethods(in Input) (string, []ssh.AuthMethod, error) {
	if in.Username == "" {
		return "", nil, ErrUsernameRequired
	}
	if len(in.Certificate) > 0 && len(in.PrivateKey) == 0 {
		return "", nil, fmt.Errorf("%w: certificate supplied without a private key", ErrBadCertificate)
	}
	if in.Password == "" && len(in.PrivateKey) == 0 {
		return "", nil, ErrNoCredential
	}

	var methods []ssh.AuthMethod
	if len(in.PrivateKey) > 0 {
		signer, err := parseSigner(in.PrivateKey, in.Passphrase)
		if err != nil {
			return "", nil, err
		}
		if len(in.Certificate) > 0 {
			signer, err = certSigner(signer, in.Certificate)
			if err != nil {
				return "", nil, err
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if in.Password != "" {
		methods = append(methods, ssh.Password(in.Password))
	}
	return in.Username, methods, nil
}

// parseSigner parses key, using passphrase when it is non-empty. Errors from
// x/crypto are deliberately not wrapped, since they can echo input.
func parseSigner(key, passphrase []byte) (ssh.Signer, error) {
	var (
		signer ssh.Signer
		err    error
	)
	if len(passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
	} else {
		signer, err = ssh.ParsePrivateKey(key)
	}
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("%w: key is encrypted and no passphrase was supplied", ErrBadPrivateKey)
		}
		return nil, fmt.Errorf("%w: key could not be parsed or decrypted", ErrBadPrivateKey)
	}
	if err := checkStrength(signer.PublicKey()); err != nil {
		return nil, err
	}
	return signer, nil
}

// checkStrength refuses DSA and RSA keys shorter than minRSABits.
func checkStrength(pub ssh.PublicKey) error {
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("%w: unsupported key type", ErrBadPrivateKey)
	}
	switch k := cpk.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return fmt.Errorf("%w: RSA key shorter than %d bits", ErrBadPrivateKey, minRSABits)
		}
	case ed25519.PublicKey, *ecdsa.PublicKey:
	default:
		return fmt.Errorf("%w: unsupported key type", ErrBadPrivateKey)
	}
	return nil
}

// certSigner wraps signer with the certificate in cert. Errors from x/crypto
// are deliberately not wrapped, since they can echo input.
func certSigner(signer ssh.Signer, cert []byte) (ssh.Signer, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cert)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate could not be parsed", ErrBadCertificate)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%w: not a certificate", ErrBadCertificate)
	}
	if c.CertType != ssh.UserCert {
		return nil, fmt.Errorf("%w: not a user certificate", ErrBadCertificate)
	}
	t := uint64(now().Unix())
	if t < c.ValidAfter {
		return nil, fmt.Errorf("%w: certificate is not yet valid", ErrBadCertificate)
	}
	if c.ValidBefore != ssh.CertTimeInfinity && t >= c.ValidBefore {
		return nil, fmt.Errorf("%w: certificate has expired", ErrBadCertificate)
	}
	if !bytes.Equal(c.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, fmt.Errorf("%w: certificate does not match the private key", ErrBadCertificate)
	}
	cs, err := ssh.NewCertSigner(c, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate does not match the private key", ErrBadCertificate)
	}
	return cs, nil
}
