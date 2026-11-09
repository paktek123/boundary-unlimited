// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package run

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/hashicorp/boundary/internal/runbook/approval"
	"github.com/hashicorp/boundary/internal/runbook/source"
)

const (
	sha    = "0123456789abcdef0123456789abcdef01234567"
	otherS = "fedcba9876543210fedcba9876543210fedcba98"
	script = "true"
	canary = "CANARY-VALUE-9f8e7d"
)

type fakeExec struct {
	calls int
	got   RenderedBinding
	res   Result
	err   error
	// order records the call relative to the emitter.
	log *[]string
}

func (f *fakeExec) Execute(_ context.Context, rb RenderedBinding) (Result, error) {
	f.calls++
	f.got = rb
	if f.log != nil {
		*f.log = append(*f.log, "execute")
	}
	return f.res, f.err
}

type logEmitter struct {
	rec runbook.RecordingEmitter
	log *[]string
}

func (l *logEmitter) Emit(ctx context.Context, e runbook.Event) error {
	if l.log != nil {
		*l.log = append(*l.log, string(e.Type))
	}
	return l.rec.Emit(ctx, e)
}

func def() runbook.Definition {
	return runbook.Definition{
		Name: "restart-svc", Interpreter: runbook.InterpreterPosixSh,
		Selector:   runbook.TargetSelector{TargetIDs: []string{"ttcp_1"}},
		Parameters: []runbook.Parameter{{Name: "SVC", Type: runbook.TypeString, Regex: "[A-Za-z0-9_.-]+", Required: true}},
	}
}

func approved(t *testing.T, s string, sh string) approval.Binding {
	t.Helper()
	d := def()
	d.Script = []byte(s)
	pin, err := source.NewPin(sh, d.Script)
	if err != nil {
		t.Fatal(err)
	}
	b, err := approval.Bind(d, pin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	r   *Runner
	ex  *fakeExec
	em  *logEmitter
	req Request
	log *[]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	log := &[]string{}
	ff := &source.FakeFetcher{}
	ff.Add(sha, "rb/restart.json", []byte(script))
	ex := &fakeExec{log: log}
	em := &logEmitter{log: log}
	return &fixture{
		r: &Runner{Fetcher: ff, Emitter: em, Executor: ex}, ex: ex, em: em, log: log,
		req: Request{
			Def: def(), RepoURL: "https://example.invalid/repo.git", Path: "rb/restart.json", SHA: sha,
			Limits: source.Limits{AllowUncountedTree: true},
			Params: map[string]string{"SVC": canary}, Approved: approved(t, script, sha),
			RunbookID: "rb_1", PrincipalID: "u_1", TargetID: "ttcp_1",
		},
	}
}

func TestRun_Success(t *testing.T) {
	f := newFixture(t)
	f.ex.res = Result{SessionID: "s_1"}
	res, err := f.r.Run(context.Background(), f.req)
	if err != nil || res.SessionID != "s_1" {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if want := "runbook.run_started,execute,runbook.run_finished"; strings.Join(*f.log, ",") != want {
		t.Fatalf("order %v, want %s", *f.log, want)
	}
	evs := f.em.rec.Events()
	if evs[1].Outcome != runbook.OutcomeSuccess || len(evs[0].ParamNames) != 1 || evs[0].ParamNames[0] != "SVC" {
		t.Fatalf("bad events: %+v", evs)
	}
	if len(f.ex.got.Invocation.Env) != 1 || f.ex.got.TargetID != "ttcp_1" {
		t.Fatalf("executor got %v", f.ex.got)
	}
	for _, e := range evs {
		if strings.Contains(fmt.Sprintf("%+v", e), canary) {
			t.Fatalf("event leaks value: %+v", e)
		}
	}
}

func TestRun_FailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, f *fixture)
		want   error
	}{
		{"invalid params", func(_ *testing.T, f *fixture) { f.req.Params = map[string]string{"SVC": "bad value!"} }, runbook.ErrInvalid},
		{"missing params", func(_ *testing.T, f *fixture) { f.req.Params = nil }, runbook.ErrInvalid},
		{"undeclared param", func(_ *testing.T, f *fixture) { f.req.Params["X"] = "1" }, runbook.ErrInvalid},
		{"sha not pinned", func(_ *testing.T, f *fixture) { f.req.SHA = "main" }, source.ErrInvalidRef},
		{"script hash mismatch", func(t *testing.T, f *fixture) {
			f.req.Approved = approved(t, "false", sha)
		}, source.ErrHashMismatch},
		{"sha mismatch", func(t *testing.T, f *fixture) {
			f.req.Approved = approved(t, script, otherS)
		}, approval.ErrMismatch},
		{"missing binding", func(_ *testing.T, f *fixture) { f.req.Approved = approval.Binding{} }, source.ErrHashMismatch},
		{"param set differs", func(t *testing.T, f *fixture) {
			b := approved(t, script, sha)
			b.ParamNames = []string{"OTHER"}
			f.req.Approved = b
		}, approval.ErrMismatch},
		{"runbook differs", func(t *testing.T, f *fixture) {
			b := approved(t, script, sha)
			b.RunbookRef = "other"
			f.req.Approved = b
		}, approval.ErrMismatch},
		{"target not selected", func(_ *testing.T, f *fixture) { f.req.TargetID = "ttcp_2" }, ErrNotPermitted},
		{"empty target", func(_ *testing.T, f *fixture) { f.req.TargetID = "" }, ErrNotPermitted},
		{"fetch error", func(_ *testing.T, f *fixture) { f.r.Fetcher = &source.FakeFetcher{Err: errors.New("boom")} }, ErrFetch},
		{"render error", func(_ *testing.T, f *fixture) { f.req.Params["SVC"] = "a\x01b" }, runbook.ErrInvalid},
		{"audit emit error", func(_ *testing.T, f *fixture) { f.em.rec.Err = errors.New("sink down") }, ErrAudit},
		{"invalid audit input", func(_ *testing.T, f *fixture) { f.req.PrincipalID = "" }, ErrAudit},
		{"not configured", func(_ *testing.T, f *fixture) { f.r.Executor = nil }, ErrInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.mutate(t, f)
			_, err := f.r.Run(context.Background(), f.req)
			if err == nil {
				t.Fatal("want error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err %v, want %v", err, tt.want)
			}
			if f.ex.calls != 0 {
				t.Fatal("Executor was called")
			}
			for _, c := range []string{canary, "sink down", "boom"} {
				if strings.Contains(err.Error(), c) {
					t.Fatalf("error leaks %q: %v", c, err)
				}
			}
			for _, e := range f.em.rec.Events() {
				if strings.Contains(fmt.Sprintf("%+v", e), canary) {
					t.Fatal("event leaks value")
				}
			}
		})
	}
}

func TestRun_RejectionIsAudited(t *testing.T) {
	f := newFixture(t)
	f.req.TargetID = "ttcp_2"
	if _, err := f.r.Run(context.Background(), f.req); !errors.Is(err, ErrNotPermitted) {
		t.Fatal(err)
	}
	evs := f.em.rec.Events()
	if len(evs) != 1 || evs[0].Type != runbook.EventRunRejected || evs[0].Outcome != runbook.OutcomeRejected {
		t.Fatalf("events: %+v", evs)
	}
}

func TestRun_ExecutorFailure(t *testing.T) {
	for _, tt := range []struct {
		name string
		res  Result
		err  error
	}{
		{"error", Result{}, errors.New("secret-bearing " + canary)},
		{"nonzero exit", Result{ExitCode: 2}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.ex.res, f.ex.err = tt.res, tt.err
			_, err := f.r.Run(context.Background(), f.req)
			if tt.err != nil && (!errors.Is(err, ErrExecute) || strings.Contains(err.Error(), canary)) {
				t.Fatalf("err %v", err)
			}
			evs := f.em.rec.Events()
			if len(evs) != 2 || evs[1].Type != runbook.EventRunFinished || evs[1].Outcome != runbook.OutcomeFailure {
				t.Fatalf("events: %+v", evs)
			}
			if strings.Contains(fmt.Sprintf("%+v", evs), canary) {
				t.Fatal("finish event leaks value")
			}
		})
	}
}

func TestRun_FinishEmitFailureIsReported(t *testing.T) {
	f := newFixture(t)
	n := 0
	f.r.Emitter = emitterFunc(func(ctx context.Context, e runbook.Event) error {
		n++
		if n == 2 {
			return errors.New("sink down")
		}
		return f.em.Emit(ctx, e)
	})
	if _, err := f.r.Run(context.Background(), f.req); !errors.Is(err, ErrAudit) {
		t.Fatalf("err %v", err)
	}
}

type emitterFunc func(context.Context, runbook.Event) error

func (f emitterFunc) Emit(ctx context.Context, e runbook.Event) error { return f(ctx, e) }

func TestRenderedBinding_NeverPrintsValues(t *testing.T) {
	f := newFixture(t)
	if _, err := f.r.Run(context.Background(), f.req); err != nil {
		t.Fatal(err)
	}
	rb := f.ex.got
	for _, s := range []string{fmt.Sprint(rb), fmt.Sprintf("%+v", rb), fmt.Sprintf("%#v", rb), fmt.Sprintf("%v", &rb)} {
		if strings.Contains(s, canary) {
			t.Fatalf("leaks value: %s", s)
		}
	}
}

func TestRun_ScopeSelector(t *testing.T) {
	f := newFixture(t)
	f.req.Def.Selector = runbook.TargetSelector{ScopeIDs: []string{"p_1"}}
	f.req.TargetID, f.req.TargetScopeID = "ttcp_9", "p_1"
	if _, err := f.r.Run(context.Background(), f.req); err != nil {
		t.Fatal(err)
	}
}

type panicExec struct{}

func (panicExec) Execute(context.Context, RenderedBinding) (Result, error) {
	panic("executor exploded " + canary)
}

func TestRun_ExecutorPanicStillAuditsFinish(t *testing.T) {
	f := newFixture(t)
	f.r.Executor = panicExec{}
	_, err := f.r.Run(context.Background(), f.req)
	if !errors.Is(err, ErrExecute) || strings.Contains(err.Error(), canary) {
		t.Fatalf("err %v", err)
	}
	evs := f.em.rec.Events()
	if len(evs) != 2 || evs[1].Type != runbook.EventRunFinished || evs[1].Outcome != runbook.OutcomeFailure {
		t.Fatalf("events: %+v", evs)
	}
}

type cancelExec struct{ cancel context.CancelFunc }

func (c cancelExec) Execute(context.Context, RenderedBinding) (Result, error) {
	c.cancel()
	return Result{}, nil
}

func TestRun_FinishAuditedAfterContextCancel(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.r.Executor = cancelExec{cancel}
	// An emitter that, like a real sink, refuses to work on a cancelled context.
	f.r.Emitter = emitterFunc(func(c context.Context, e runbook.Event) error {
		if c.Err() != nil {
			return c.Err()
		}
		return f.em.Emit(c, e)
	})
	if _, err := f.r.Run(ctx, f.req); err != nil {
		t.Fatalf("err %v", err)
	}
	evs := f.em.rec.Events()
	if len(evs) != 2 || evs[1].Type != runbook.EventRunFinished {
		t.Fatalf("finish event missing after cancel: %+v", evs)
	}
}
