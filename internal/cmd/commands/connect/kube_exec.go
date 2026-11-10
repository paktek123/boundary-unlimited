// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package connect

import (
	"errors"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/api/targets"
)

// kubeCredentialMap returns the decoded json credential for a session
// credential, or nil if it is not a json credential.
func kubeCredentialMap(c *targets.SessionCredential) map[string]any {
	if c == nil || c.CredentialSource == nil || c.CredentialSource.CredentialType != "json" {
		return nil
	}
	if c.Secret != nil && c.Secret.Decoded != nil {
		return c.Secret.Decoded
	}
	return c.Credential
}

// kubeExecInputs is the result of preparing a kubernetes connect session.
type kubeExecInputs struct {
	// Env holds environment entries (KUBECONFIG) for the client process.
	Env []string
	// Cleanup removes the generated kubeconfig; it is never nil.
	Cleanup func() error
	// Used is the credential that was consumed, or nil if none was brokered.
	Used *targets.SessionCredential
}

// prepareKubeconfig builds a private kubeconfig from the brokered json
// credential of the session, if there is one. Without a json credential it
// returns (nil, nil) and the caller keeps the flag-only behaviour. It fails
// closed: more than one json credential, a non-https scheme, a missing server
// name, an unsupported credential shape or an exec-plugin kubeconfig all
// return an error and leave no file behind. Errors never contain credential
// material.
func (f *kubeFlags) prepareKubeconfig(endpoint, localAddr string, sessionCreds []*targets.SessionCredential) (*kubeExecInputs, error) {
	var picked *targets.SessionCredential
	var pickedMap map[string]any
	for _, sc := range sessionCreds {
		m := kubeCredentialMap(sc)
		if m == nil {
			continue
		}
		if picked != nil {
			return nil, errors.New("more than one json credential was brokered; kubernetes targets accept exactly one")
		}
		picked, pickedMap = sc, m
	}
	if picked == nil {
		return nil, nil
	}
	if f.flagKubeScheme != "https" {
		return nil, errors.New("brokered kubernetes credentials require the https scheme")
	}

	host := f.flagKubeHost
	if host == "" && endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, errors.New("error parsing endpoint URL")
		}
		host = u.Hostname()
	}
	host = strings.TrimSuffix(host, "/")

	path, cleanup, err := kubeconfigFromCredential(pickedMap, localAddr, host)
	if err != nil {
		return nil, err
	}
	return &kubeExecInputs{
		Env:     []string{"KUBECONFIG=" + path},
		Cleanup: cleanup,
		Used:    picked,
	}, nil
}
