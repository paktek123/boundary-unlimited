// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

const (
	kubeconfigClusterName = "boundary"
	kubeconfigUserName    = "boundary"
	kubeconfigContextName = "boundary"
	kubeconfigFileName    = "kubeconfig"
)

// kubeconfigInput describes the pieces needed to build a kubeconfig that
// points kubectl at the local Boundary proxy.
type kubeconfigInput struct {
	// ProxyAddr is the local proxy listener, host:port.
	ProxyAddr string
	// TLSServerName is the name the API server certificate is verified
	// against. It is required because the certificate is not issued for the
	// local listener address.
	TLSServerName string
	// CACertPEM is an optional PEM CA bundle for the API server. When empty
	// the client's own trust store is used.
	CACertPEM []byte
	// Token is a bearer token. Mutually exclusive with the client cert/key.
	Token string
	// ClientCertPEM and ClientKeyPEM are PEM client certificate credentials.
	// Both must be set together.
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

type kubeconfigDoc struct {
	APIVersion     string                `yaml:"apiVersion"`
	Kind           string                `yaml:"kind"`
	Clusters       []kubeconfigNamedItem `yaml:"clusters"`
	Users          []kubeconfigNamedItem `yaml:"users"`
	Contexts       []kubeconfigNamedItem `yaml:"contexts"`
	CurrentContext string                `yaml:"current-context"`
}

type kubeconfigNamedItem struct {
	Name    string         `yaml:"name"`
	Cluster map[string]any `yaml:"cluster,omitempty"`
	User    map[string]any `yaml:"user,omitempty"`
	Context map[string]any `yaml:"context,omitempty"`
}

// buildKubeconfig returns a kubeconfig document for the given input. TLS
// verification is never disabled: insecure-skip-tls-verify is not generated.
// Errors never contain credential material.
func buildKubeconfig(in kubeconfigInput) ([]byte, error) {
	host, port, err := net.SplitHostPort(in.ProxyAddr)
	if err != nil || host == "" {
		return nil, errors.New("kubeconfig: proxy address must be host:port")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return nil, errors.New("kubeconfig: proxy address has an invalid port")
	}
	if in.TLSServerName == "" {
		return nil, errors.New("kubeconfig: tls server name is required")
	}

	hasToken := in.Token != ""
	hasCert := len(in.ClientCertPEM) > 0 || len(in.ClientKeyPEM) > 0
	switch {
	case hasToken && hasCert:
		return nil, errors.New("kubeconfig: provide either a bearer token or a client certificate, not both")
	case !hasToken && !hasCert:
		return nil, errors.New("kubeconfig: a bearer token or a client certificate is required")
	case hasCert && (len(in.ClientCertPEM) == 0 || len(in.ClientKeyPEM) == 0):
		return nil, errors.New("kubeconfig: client certificate and key must both be provided")
	}

	cluster := map[string]any{
		"server":          "https://" + net.JoinHostPort(host, port),
		"tls-server-name": in.TLSServerName,
	}
	if len(in.CACertPEM) > 0 {
		cluster["certificate-authority-data"] = base64.StdEncoding.EncodeToString(in.CACertPEM)
	}

	user := map[string]any{}
	if hasToken {
		user["token"] = in.Token
	} else {
		user["client-certificate-data"] = base64.StdEncoding.EncodeToString(in.ClientCertPEM)
		user["client-key-data"] = base64.StdEncoding.EncodeToString(in.ClientKeyPEM)
	}

	doc := kubeconfigDoc{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters:   []kubeconfigNamedItem{{Name: kubeconfigClusterName, Cluster: cluster}},
		Users:      []kubeconfigNamedItem{{Name: kubeconfigUserName, User: user}},
		Contexts: []kubeconfigNamedItem{{Name: kubeconfigContextName, Context: map[string]any{
			"cluster": kubeconfigClusterName,
			"user":    kubeconfigUserName,
		}}},
		CurrentContext: kubeconfigContextName,
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, errors.New("kubeconfig: unable to encode document")
	}
	return out, nil
}

// rejectExecKubeconfig returns an error if the given kubeconfig document
// contains any user with an exec plugin (which would run arbitrary local
// commands) or fails to parse. The error never contains document content.
func rejectExecKubeconfig(raw []byte) error {
	var doc struct {
		Users []struct {
			User map[string]any `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return errors.New("kubeconfig: unable to parse document")
	}
	for _, u := range doc.Users {
		if _, ok := u.User["exec"]; ok {
			return errors.New("kubeconfig: exec-plugin users are not supported")
		}
		if _, ok := u.User["auth-provider"]; ok {
			return errors.New("kubeconfig: auth-provider users are not supported")
		}
	}
	return nil
}

// writeKubeconfigTemp writes content to a mode 0600 file inside a freshly
// created private (0700) directory and returns its path along with a cleanup
// function that removes the file and the directory.
func writeKubeconfigTemp(content []byte) (string, func() error, error) {
	dir, err := os.MkdirTemp("", "boundary-kubeconfig-")
	if err != nil {
		return "", nil, fmt.Errorf("kubeconfig: unable to create temp dir: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(dir) }

	path := dir + string(os.PathSeparator) + kubeconfigFileName
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = cleanup()
		return "", nil, fmt.Errorf("kubeconfig: unable to create file: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = cleanup()
		return "", nil, errors.New("kubeconfig: unable to write file")
	}
	if err := f.Close(); err != nil {
		_ = cleanup()
		return "", nil, errors.New("kubeconfig: unable to write file")
	}
	return path, cleanup, nil
}
