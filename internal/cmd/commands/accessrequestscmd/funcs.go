// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package accessrequestscmd

// This file is adapted from sessionscmd/funcs.go and so keeps its upstream
// header.

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accessrequests"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

const (
	flagJustification = "justification"
	flagGrant         = "grant"
	flagDuration      = "duration-seconds"
)

func init() {
	// The access request API takes no name or description.
	flagsMap["create"] = []string{"scope-id"}
	extraActionsFlagsMapFunc = extraActionsFlagsMapFuncImpl
	extraFlagsFunc = extraFlagsFuncImpl
	extraFlagsHandlingFunc = extraFlagsHandlingFuncImpl
	executeExtraActions = executeExtraActionsImpl
}

func extraActionsFlagsMapFuncImpl() map[string][]string {
	return map[string][]string{
		"create":  {flagJustification, flagGrant, flagDuration},
		"approve": {"id"},
		"deny":    {"id"},
		"cancel":  {"id"},
		"revoke":  {"id"},
	}
}

type extraCmdVars struct {
	flagJustification string
	flagGrants        []string
	flagDuration      string
}

func extraFlagsFuncImpl(c *Command, set *base.FlagSets, f *base.FlagSet) {
	for _, name := range flagsMap[c.Func] {
		switch name {
		case flagJustification:
			f.StringVar(&base.StringVar{
				Name:   flagJustification,
				Target: &c.flagJustification,
				Usage:  "The justification for the request. It is treated as untrusted text and is length limited by the server.",
			})
		case flagGrant:
			f.StringSliceVar(&base.StringSliceVar{
				Name:   flagGrant,
				Target: &c.flagGrants,
				Usage:  "A grant string being requested. May be specified multiple times.",
			})
		case flagDuration:
			f.StringVar(&base.StringVar{
				Name:   flagDuration,
				Target: &c.flagDuration,
				Usage:  "The requested access duration, as an integer number of seconds or a duration string such as 1h.",
			})
		}
	}
}

func extraFlagsHandlingFuncImpl(c *Command, _ *base.FlagSets, opts *[]accessrequests.Option) bool {
	if c.flagJustification != "" {
		*opts = append(*opts, accessrequests.WithJustification(c.flagJustification))
	}
	if len(c.flagGrants) > 0 {
		*opts = append(*opts, accessrequests.WithGrants(c.flagGrants))
	}
	if c.flagDuration != "" {
		secs, ok := parseDurationSeconds(c.flagDuration)
		if !ok {
			c.UI.Error(fmt.Sprintf("Error parsing %q as a positive duration of at most %d seconds", c.flagDuration, uint64(math.MaxUint32)))
			return false
		}
		*opts = append(*opts, accessrequests.WithDurationSeconds(secs))
	}
	return true
}

// parseDurationSeconds parses an integer number of seconds or a duration
// string. It rejects zero, negative and out-of-range values.
func parseDurationSeconds(in string) (uint32, bool) {
	if n, err := strconv.ParseUint(in, 10, 32); err == nil {
		return uint32(n), n > 0
	}
	d, err := time.ParseDuration(in)
	if err != nil || d < time.Second || d.Seconds() > math.MaxUint32 {
		return 0, false
	}
	return uint32(d.Seconds()), true
}

func (c *Command) extraHelpFunc(helpMap map[string]func() string) string {
	var helpStr string
	switch c.Func {
	case "":
		return base.WrapForHelpText([]string{
			"Usage: boundary access-requests [sub command] [options] [args]",
			"",
			"  This command allows operations on Boundary access requests.",
			"",
			"    Create an access request:",
			"",
			`      $ boundary access-requests create -scope-id p_1234567890 -grant 'ids=*;type=target;actions=authorize-session' -duration-seconds 3600 -justification 'incident 42'`,
			"",
			"  Please see the access-requests subcommand help for detailed usage information.",
		})
	case "create":
		helpStr = base.WrapForHelpText([]string{
			"Usage: boundary access-requests create [options] [args]",
			"",
			"  Create an access request for explicit grants. Nothing is granted until an approver, who must hold the requested grants, approves it. Example:",
			"",
			`    $ boundary access-requests create -scope-id p_1234567890 -grant 'ids=*;type=target;actions=authorize-session' -duration-seconds 3600`,
			"",
			"",
		})
	case "approve", "deny", "cancel", "revoke":
		note := ""
		if c.Func == "revoke" {
			note = " Revoking may be refused by the server until it is supported."
		}
		helpStr = base.WrapForHelpText([]string{
			fmt.Sprintf("Usage: boundary access-requests %s [options] [args]", c.Func),
			"",
			fmt.Sprintf("  %s the access request specified by ID. The server decides who may do this; approval is never allowed for the requester.%s Example:", c.Func, note),
			"",
			fmt.Sprintf("    $ boundary access-requests %s -id ar_1234567890", c.Func),
			"",
			"",
		})
	default:
		helpStr = helpMap["base"]()
	}
	return helpStr + c.Flags().Help()
}

func executeExtraActionsImpl(c *Command, origResp *api.Response, origItem *accessrequests.AccessRequest, origItems []*accessrequests.AccessRequest, origError error, client *accessrequests.Client, version uint32, opts []accessrequests.Option) (*api.Response, *accessrequests.AccessRequest, []*accessrequests.AccessRequest, error) {
	var (
		res *accessrequests.AccessRequestUpdateResult
		err error
	)
	switch c.Func {
	case "approve":
		res, err = client.Approve(c.Context, c.FlagId, version, opts...)
	case "deny":
		res, err = client.Deny(c.Context, c.FlagId, version, opts...)
	case "cancel":
		res, err = client.Cancel(c.Context, c.FlagId, version, opts...)
	case "revoke":
		res, err = client.Revoke(c.Context, c.FlagId, version, opts...)
	default:
		return origResp, origItem, origItems, origError
	}
	if err != nil {
		return nil, nil, nil, err
	}
	return res.GetResponse(), res.GetItem(), nil, nil
}

// The justification is intentionally not printed in list output.
func (c *Command) printListTable(items []*accessrequests.AccessRequest) string {
	if len(items) == 0 {
		return "No access requests found"
	}
	output := []string{"", "Access request information:"}
	for i, item := range items {
		if i > 0 {
			output = append(output, "")
		}
		id := item.Id
		if id == "" {
			id = "(not available)"
		}
		output = append(output, fmt.Sprintf("  ID:                    %s", id))
		if c.FlagRecursive && item.ScopeId != "" {
			output = append(output, fmt.Sprintf("    Scope ID:            %s", item.ScopeId))
		}
		if item.State != "" {
			output = append(output, fmt.Sprintf("    State:               %s", item.State))
		}
		if item.RequesterId != "" {
			output = append(output, fmt.Sprintf("    Requester ID:        %s", item.RequesterId))
		}
		if !item.CreatedTime.IsZero() {
			output = append(output, fmt.Sprintf("    Created Time:        %s", item.CreatedTime.Local().Format(time.RFC1123)))
		}
	}
	return base.WrapForHelpText(output)
}

func printItemTable(item *accessrequests.AccessRequest, resp *api.Response) string {
	nonAttributeMap := map[string]any{}
	if item.Id != "" {
		nonAttributeMap["ID"] = item.Id
	}
	if item.ScopeId != "" {
		nonAttributeMap["Scope ID"] = item.ScopeId
	}
	if item.Version != 0 {
		nonAttributeMap["Version"] = item.Version
	}
	if item.State != "" {
		nonAttributeMap["State"] = item.State
	}
	if item.RequesterId != "" {
		nonAttributeMap["Requester ID"] = item.RequesterId
	}
	if item.DurationSeconds != 0 {
		nonAttributeMap["Duration Seconds"] = item.DurationSeconds
	}
	if item.Justification != "" {
		nonAttributeMap["Justification"] = item.Justification
	}
	if item.DecidedBy != "" {
		nonAttributeMap["Decided By"] = item.DecidedBy
	}
	if !item.CreatedTime.IsZero() {
		nonAttributeMap["Created Time"] = item.CreatedTime.Local().Format(time.RFC1123)
	}
	if !item.DecidedTime.IsZero() {
		nonAttributeMap["Decided Time"] = item.DecidedTime.Local().Format(time.RFC1123)
	}
	if !item.ExpirationTime.IsZero() {
		nonAttributeMap["Expiration Time"] = item.ExpirationTime.Local().Format(time.RFC1123)
	}

	maxLength := base.MaxAttributesLength(nonAttributeMap, nil, nil)
	ret := []string{
		"",
		"Access request information:",
		base.WrapMap(2, maxLength+2, nonAttributeMap),
	}
	if len(item.Grants) > 0 {
		ret = append(ret, "", "  Grants:")
		for _, g := range item.Grants {
			ret = append(ret, fmt.Sprintf("    %s", g))
		}
	}
	return base.WrapForHelpText(ret)
}
