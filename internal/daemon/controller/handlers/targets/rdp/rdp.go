// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package rdp

import (
	"context"
	"math"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/rdp"
	rdpStore "github.com/hashicorp/boundary/internal/target/rdp/store"
	"github.com/hashicorp/boundary/internal/target/store"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
)

const (
	defaultPortField       = "attributes.default_port"
	defaultClientPortField = "attributes.default_client_port"
	storageBucketIdField   = "attributes.storage_bucket_id"
	enableRecordingField   = "attributes.enable_session_recording"

	// defaultTargetPort is used when a default port is not provided.
	defaultTargetPort = 3389
)

type attribute struct {
	*pb.RdpTargetAttributes
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
	vetRecording(a.RdpTargetAttributes, badFields)
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
	if handlers.MaskContains(p, storageBucketIdField) || handlers.MaskContains(p, enableRecordingField) {
		vetRecording(a.RdpTargetAttributes, badFields)
	}
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

// vetRecording rejects attempts to enable session recording, which is not
// supported by this build. Leaving the fields unset or false/empty is allowed.
func vetRecording(a *pb.RdpTargetAttributes, badFields map[string]string) {
	if a.GetEnableSessionRecording().GetValue() {
		badFields[enableRecordingField] = "Session recording is not supported."
	}
	if a.GetStorageBucketId().GetValue() != "" {
		badFields[storageBucketIdField] = "Storage buckets are not supported."
	}
}

func newAttribute(m any) targets.Attributes {
	a := &attribute{
		&pb.RdpTargetAttributes{},
	}
	if rdpAttr, ok := m.(*pb.Target_RdpTargetAttributes); ok {
		a.RdpTargetAttributes = rdpAttr.RdpTargetAttributes
	}
	return a
}

func setAttributes(t target.Target, out *pb.Target) error {
	if t == nil {
		return nil
	}

	attrs := &pb.Target_RdpTargetAttributes{
		RdpTargetAttributes: &pb.RdpTargetAttributes{},
	}
	if t.GetDefaultPort() > 0 {
		attrs.RdpTargetAttributes.DefaultPort = &wrappers.UInt32Value{Value: t.GetDefaultPort()}
	}
	if t.GetDefaultClientPort() > 0 {
		attrs.RdpTargetAttributes.DefaultClientPort = &wrappers.UInt32Value{Value: t.GetDefaultClientPort()}
	}

	out.Attrs = attrs
	return nil
}

func noopSessionValidation(context.Context, *session.Session) error { return nil }

func init() {
	var maskManager handlers.MaskManager
	var err error

	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&rdpStore.Target{}, &store.TargetAddress{}},
		handlers.MaskSource{&pb.Target{}, &pb.RdpTargetAttributes{}},
	); err != nil {
		panic(err)
	}

	targets.Register(rdp.Subtype, maskManager, newAttribute, setAttributes, noopSessionValidation)
}
