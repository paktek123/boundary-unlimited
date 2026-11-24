// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package kubernetes

import (
	"context"
	"math"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/kubernetes"
	kubeStore "github.com/hashicorp/boundary/internal/target/kubernetes/store"
	"github.com/hashicorp/boundary/internal/target/store"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
)

const (
	defaultPortField       = "attributes.default_port"
	defaultClientPortField = "attributes.default_client_port"

	// defaultTargetPort is used when a default port is not provided.
	defaultTargetPort = 443
)

type attribute struct {
	*pb.KubernetesTargetAttributes
}

func (a *attribute) Options() []target.Option {
	var opts []target.Option
	if a.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(a.GetDefaultPort().GetValue()))
	} else {
		opts = append(opts, target.WithDefaultPort(defaultTargetPort))
	}
	if a.GetDefaultClientPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultClientPort(a.GetDefaultClientPort().GetValue()))
	}
	return opts
}

func (a *attribute) Vet() map[string]string {
	badFields := map[string]string{}
	if a.GetDefaultPort() != nil {
		if a.GetDefaultPort().GetValue() == 0 {
			badFields[defaultPortField] = "This field cannot be set to zero."
		}
		if a.GetDefaultPort().GetValue() > math.MaxUint16 {
			badFields[defaultPortField] = "Value is greater than maximum port number."
		}
	}
	if a.GetDefaultClientPort() != nil {
		if a.GetDefaultClientPort().GetValue() == 0 {
			badFields[defaultClientPortField] = "This field cannot be set to zero."
		}
		if a.GetDefaultClientPort().GetValue() > math.MaxUint16 {
			badFields[defaultClientPortField] = "Value is greater than maximum port number."
		}
	}
	return badFields
}

func (a *attribute) VetForUpdate(p []string) map[string]string {
	badFields := map[string]string{}
	if handlers.MaskContains(p, defaultPortField) {
		if a.GetDefaultPort() == nil {
			badFields[defaultPortField] = "This field is required."
		} else {
			if a.GetDefaultPort().GetValue() == 0 {
				badFields[defaultPortField] = "This cannot be set to zero."
			}
			if a.GetDefaultPort().GetValue() > math.MaxUint16 {
				badFields[defaultPortField] = "Value is greater than maximum port number."
			}
		}
	}
	if handlers.MaskContains(p, defaultClientPortField) && a.GetDefaultClientPort() != nil {
		if a.GetDefaultClientPort().GetValue() == 0 {
			badFields[defaultClientPortField] = "This cannot be set to zero."
		}
		if a.GetDefaultClientPort().GetValue() > math.MaxUint16 {
			badFields[defaultClientPortField] = "Value is greater than maximum port number."
		}
	}
	return badFields
}

func newAttribute(m any) targets.Attributes {
	a := &attribute{
		&pb.KubernetesTargetAttributes{},
	}
	if kubeAttr, ok := m.(*pb.Target_KubernetesTargetAttributes); ok {
		a.KubernetesTargetAttributes = kubeAttr.KubernetesTargetAttributes
	}
	return a
}

func setAttributes(t target.Target, out *pb.Target) error {
	if t == nil {
		return nil
	}

	attrs := &pb.Target_KubernetesTargetAttributes{
		KubernetesTargetAttributes: &pb.KubernetesTargetAttributes{},
	}
	if t.GetDefaultPort() > 0 {
		attrs.KubernetesTargetAttributes.DefaultPort = &wrappers.UInt32Value{Value: t.GetDefaultPort()}
	}
	if t.GetDefaultClientPort() > 0 {
		attrs.KubernetesTargetAttributes.DefaultClientPort = &wrappers.UInt32Value{Value: t.GetDefaultClientPort()}
	}

	out.Attrs = attrs
	return nil
}

// noopSessionValidation: nothing about a kubernetes target is validated at
// session time. Sessions are still refused by the worker handler, which has no
// proxy enabled (enforcement-first, see #26).
func noopSessionValidation(context.Context, *session.Session) error { return nil }

func init() {
	var maskManager handlers.MaskManager
	var err error

	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&kubeStore.Target{}, &store.TargetAddress{}},
		handlers.MaskSource{&pb.Target{}, &pb.KubernetesTargetAttributes{}},
	); err != nil {
		panic(err)
	}

	targets.Register(kubernetes.Subtype, maskManager, newAttribute, setAttributes, noopSessionValidation)
}
