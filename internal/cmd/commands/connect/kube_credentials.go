// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"encoding/base64"
	"errors"

	"github.com/hashicorp/boundary/internal/cmd/commands/connect/kubecreds"
)

// kubeconfigFromCredential turns a brokered kubernetes credential into a
// private kubeconfig file that points kubectl at the local proxy listener.
// The credential is validated with kubecreds.Parse, then rebuilt through
// buildKubeconfig so the server is always localAddr and TLS verification is
// never disabled. tlsServerName, when non-empty, takes precedence over any
// tls-server-name carried by a full kubeconfig credential.
//
// It fails closed: any error returns no path and no file is left behind. On
// success the caller must call cleanup. Errors never contain credential
// material.
func kubeconfigFromCredential(cred map[string]any, localAddr, tlsServerName string) (string, func() error, error) {
	res, err := kubecreds.Parse(cred)
	if err != nil {
		return "", nil, err
	}

	in := kubeconfigInput{
		ProxyAddr:     localAddr,
		TLSServerName: tlsServerName,
		Token:         res.Token,
	}
	if in.TLSServerName == "" {
		in.TLSServerName = res.TLSServerName
	}
	if res.CertificateAuthorityData != "" {
		if in.CACertPEM, err = base64.StdEncoding.DecodeString(res.CertificateAuthorityData); err != nil {
			return "", nil, errors.New("kubeconfig: certificate authority data is not valid base64")
		}
	}
	if res.ClientCertificateData != "" || res.ClientKeyData != "" {
		if in.ClientCertPEM, err = base64.StdEncoding.DecodeString(res.ClientCertificateData); err != nil {
			return "", nil, errors.New("kubeconfig: client certificate data is not valid base64")
		}
		if in.ClientKeyPEM, err = base64.StdEncoding.DecodeString(res.ClientKeyData); err != nil {
			return "", nil, errors.New("kubeconfig: client key data is not valid base64")
		}
	}

	doc, err := buildKubeconfig(in)
	if err != nil {
		return "", nil, err
	}
	if err := rejectExecKubeconfig(doc); err != nil {
		return "", nil, err
	}

	path, cleanup, err := writeKubeconfigTemp(doc)
	if err != nil {
		return "", nil, err
	}
	return path, cleanup, nil
}
