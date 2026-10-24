// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package kubecreds validates and normalises brokered credentials for
// `boundary connect kube`, implementing the credential-shape rules of
// docs/rfc/kubernetes-target.md ("Credentials"). It only rejects or
// normalises; it enables nothing by itself and is not yet wired into the
// command. Every rule fails closed: unknown shapes, parse errors and empty
// values are errors, and error messages never contain token or key material.
package kubecreds

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrUnsupportedShape is returned for credentials that match no supported shape.
var ErrUnsupportedShape = errors.New("unsupported credential shape")

// Shape is the recognised credential shape.
type Shape string

const (
	// ShapeBearerToken is a json credential with a bearer `token`.
	ShapeBearerToken Shape = "bearer-token"
	// ShapeClientCert is a json credential with client-certificate-data and
	// client-key-data.
	ShapeClientCert Shape = "client-certificate"
	// ShapeKubeconfig is a complete kubeconfig.
	ShapeKubeconfig Shape = "kubeconfig"
)

// Result is the typed outcome of Parse.
type Result struct {
	Shape Shape

	// Token is set for ShapeBearerToken and for kubeconfigs whose selected
	// user authenticates with a bearer token.
	Token string
	// ClientCertificateData and ClientKeyData are base64 encoded PEM, set for
	// ShapeClientCert and for kubeconfigs whose selected user uses them.
	ClientCertificateData string
	ClientKeyData         string

	// The following are set only for ShapeKubeconfig and describe the single
	// cluster selected for the target through current-context. Server is
	// informational: the caller rewrites it to the local listener.
	Server                   string
	CertificateAuthorityData string
	TLSServerName            string
}

type kubeconfig struct {
	Clusters []struct {
		Name    string         `yaml:"name" json:"name"`
		Cluster map[string]any `yaml:"cluster" json:"cluster"`
	} `yaml:"clusters" json:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name" json:"name"`
		Context struct {
			Cluster string `yaml:"cluster" json:"cluster"`
			User    string `yaml:"user" json:"user"`
		} `yaml:"context" json:"context"`
	} `yaml:"contexts" json:"contexts"`
	Users []struct {
		Name string         `yaml:"name" json:"name"`
		User map[string]any `yaml:"user" json:"user"`
	} `yaml:"users" json:"users"`
	CurrentContext string `yaml:"current-context" json:"current-context"`
}

// Parse classifies and validates the decoded json credential map of a
// brokered credential.
func Parse(cred map[string]any) (*Result, error) {
	if len(cred) == 0 {
		return nil, fmt.Errorf("%w: empty credential", ErrUnsupportedShape)
	}
	_, hasToken := cred["token"]
	_, hasCert := cred["client-certificate-data"]
	_, hasKey := cred["client-key-data"]
	_, hasKubeconfig := cred["kubeconfig"]
	_, hasClusters := cred["clusters"]
	isCfg := hasKubeconfig || hasClusters

	switch {
	case isCfg && (hasToken || hasCert || hasKey):
		return nil, fmt.Errorf("%w: kubeconfig mixed with other credential fields", ErrUnsupportedShape)
	case isCfg:
		return parseKubeconfig(cred, hasKubeconfig)
	case hasToken && (hasCert || hasKey):
		return nil, fmt.Errorf("%w: token mixed with client certificate", ErrUnsupportedShape)
	case hasToken:
		tok, err := parseToken(cred["token"])
		if err != nil {
			return nil, err
		}
		return &Result{Shape: ShapeBearerToken, Token: tok}, nil
	case hasCert || hasKey:
		c, k, err := parseClientCert(cred["client-certificate-data"], cred["client-key-data"])
		if err != nil {
			return nil, err
		}
		return &Result{Shape: ShapeClientCert, ClientCertificateData: c, ClientKeyData: k}, nil
	}
	return nil, ErrUnsupportedShape
}

func parseToken(v any) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", errors.New("token must be a non-empty string")
	}
	if strings.TrimSpace(s) != s || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("token contains whitespace or control characters")
	}
	return s, nil
}

func parseClientCert(certV, keyV any) (string, string, error) {
	c, cok := certV.(string)
	k, kok := keyV.(string)
	if !cok || !kok || c == "" || k == "" {
		return "", "", errors.New("client-certificate-data and client-key-data are both required and must be non-empty strings")
	}
	cb, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return "", "", errors.New("client-certificate-data is not valid base64")
	}
	kb, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return "", "", errors.New("client-key-data is not valid base64")
	}
	if _, err := tls.X509KeyPair(cb, kb); err != nil {
		return "", "", errors.New("client certificate and key are not a valid PEM key pair")
	}
	return c, k, nil
}

func parseKubeconfig(cred map[string]any, wrapped bool) (*Result, error) {
	var cfg kubeconfig
	if wrapped {
		if len(cred) != 1 {
			return nil, fmt.Errorf("%w: unexpected fields next to kubeconfig", ErrUnsupportedShape)
		}
		s, ok := cred["kubeconfig"].(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, errors.New("kubeconfig must be a non-empty string")
		}
		if err := yaml.Unmarshal([]byte(s), &cfg); err != nil {
			return nil, errors.New("kubeconfig could not be parsed")
		}
	} else {
		b, err := json.Marshal(cred)
		if err != nil {
			return nil, errors.New("kubeconfig could not be parsed")
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, errors.New("kubeconfig could not be parsed")
		}
	}

	// Whole-file rules: apply to every cluster and user, selected or not.
	for _, c := range cfg.Clusters {
		if v, ok := c.Cluster["insecure-skip-tls-verify"]; ok && v != false {
			return nil, fmt.Errorf("cluster %q: insecure-skip-tls-verify is not allowed", c.Name)
		}
		if _, ok := c.Cluster["certificate-authority"]; ok {
			return nil, fmt.Errorf("cluster %q: file path references are not allowed; use certificate-authority-data", c.Name)
		}
		if _, ok := c.Cluster["proxy-url"]; ok {
			return nil, fmt.Errorf("cluster %q: proxy-url is not allowed", c.Name)
		}
	}
	for _, u := range cfg.Users {
		for _, f := range []string{"exec", "auth-provider"} {
			if _, ok := u.User[f]; ok {
				return nil, fmt.Errorf("user %q: %s is not allowed", u.Name, f)
			}
		}
		for _, f := range []string{"tokenFile", "client-certificate", "client-key", "username", "password", "act-as", "act-as-groups", "act-as-uid"} {
			if _, ok := u.User[f]; ok {
				return nil, fmt.Errorf("user %q: %s is not allowed", u.Name, f)
			}
		}
	}

	if cfg.CurrentContext == "" {
		return nil, errors.New("kubeconfig has no current-context; the target cluster cannot be identified")
	}
	var clusterName, userName string
	found := false
	for _, c := range cfg.Contexts {
		if c.Name == cfg.CurrentContext {
			if found {
				return nil, errors.New("kubeconfig defines the current-context more than once")
			}
			found = true
			clusterName, userName = c.Context.Cluster, c.Context.User
		}
	}
	if !found {
		return nil, errors.New("kubeconfig current-context does not exist")
	}

	res := &Result{Shape: ShapeKubeconfig}
	n := 0
	for _, c := range cfg.Clusters {
		if c.Name != clusterName {
			continue
		}
		n++
		res.Server, _ = c.Cluster["server"].(string)
		res.CertificateAuthorityData, _ = c.Cluster["certificate-authority-data"].(string)
		res.TLSServerName, _ = c.Cluster["tls-server-name"].(string)
	}
	if n != 1 {
		return nil, errors.New("kubeconfig current-context must reference exactly one defined cluster")
	}
	if res.CertificateAuthorityData != "" {
		if _, err := base64.StdEncoding.DecodeString(res.CertificateAuthorityData); err != nil {
			return nil, errors.New("certificate-authority-data is not valid base64")
		}
	}

	n = 0
	var user map[string]any
	for _, u := range cfg.Users {
		if u.Name == userName {
			n++
			user = u.User
		}
	}
	if n != 1 {
		return nil, errors.New("kubeconfig current-context must reference exactly one defined user")
	}
	tokV, hasTok := user["token"]
	certV, hasCert := user["client-certificate-data"]
	keyV, hasKey := user["client-key-data"]
	switch {
	case hasTok && (hasCert || hasKey):
		return nil, errors.New("selected user mixes token and client certificate authentication")
	case hasTok:
		tok, err := parseToken(tokV)
		if err != nil {
			return nil, err
		}
		res.Token = tok
	case hasCert || hasKey:
		c, k, err := parseClientCert(certV, keyV)
		if err != nil {
			return nil, err
		}
		res.ClientCertificateData, res.ClientKeyData = c, k
	default:
		return nil, errors.New("selected user has no supported credentials (token or client certificate)")
	}
	return res, nil
}
