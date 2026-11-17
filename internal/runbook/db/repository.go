// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

// Package db is the database-backed runbook.Repository. It writes through the
// oplog. Nothing registers it in the controller and no API uses it yet.
//
// Script bodies are never stored, and database errors are never wrapped into
// the errors returned here, because they can echo column values: errors carry
// fixed text only.
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/runbook"
	"github.com/hashicorp/boundary/internal/runbook/store"
	"google.golang.org/protobuf/proto"
)

const tableName = "runbook_definition"

// dbRow is the gorm and oplog model for the runbook_definition table.
type dbRow struct {
	*store.RunbookDefinition
	tableName string `gorm:"-"`
}

func allocRow() *dbRow { return &dbRow{RunbookDefinition: &store.RunbookDefinition{}} }

// TableName implements oplog.ReplayableMessage.
func (r *dbRow) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return tableName
}

// SetTableName implements oplog.ReplayableMessage.
func (r *dbRow) SetTableName(name string) { r.tableName = name }

func (r *dbRow) clone() *dbRow {
	return &dbRow{RunbookDefinition: proto.Clone(r.RunbookDefinition).(*store.RunbookDefinition)}
}

// Repository is the database-backed runbook.Repository.
type Repository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
}

var _ runbook.Repository = (*Repository)(nil)

// NewRepository returns a Repository. All arguments are required.
func NewRepository(ctx context.Context, r db.Reader, w db.Writer, k *kms.Kms) (*Repository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("%w: nil db reader", runbook.ErrInvalidInput)
	case w == nil:
		return nil, fmt.Errorf("%w: nil db writer", runbook.ErrInvalidInput)
	case k == nil:
		return nil, fmt.Errorf("%w: nil kms", runbook.ErrInvalidInput)
	}
	return &Repository{reader: r, writer: w, kms: k}, nil
}

func toRow(d runbook.StoredDefinition) (*dbRow, error) {
	params := d.Parameters
	if params == nil {
		params = []runbook.Parameter{}
	}
	pj, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("%w: parameters not encodable", runbook.ErrInvalidInput)
	}
	sj, err := json.Marshal(d.Selector)
	if err != nil {
		return nil, fmt.Errorf("%w: selector not encodable", runbook.ErrInvalidInput)
	}
	row := allocRow()
	row.PublicId = d.Id
	row.ScopeId = d.ScopeId
	row.Name = d.Name
	row.Description = d.Description
	row.Interpreter = d.Interpreter
	row.SourceCommitSha = d.SourceCommitSHA
	row.ScriptPath = d.ScriptPath
	row.ScriptSha256 = d.ScriptSHA256
	row.Parameters = string(pj)
	row.TargetSelector = string(sj)
	return row, nil
}

func fromRow(row *dbRow) (runbook.StoredDefinition, error) {
	d := runbook.StoredDefinition{
		Id:              row.PublicId,
		ScopeId:         row.ScopeId,
		Name:            row.Name,
		Description:     row.Description,
		Interpreter:     row.Interpreter,
		SourceCommitSHA: row.SourceCommitSha,
		ScriptPath:      row.ScriptPath,
		ScriptSHA256:    row.ScriptSha256,
		Version:         row.Version,
	}
	if err := json.Unmarshal([]byte(row.Parameters), &d.Parameters); err != nil {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: stored parameters are not valid", runbook.ErrInvalidInput)
	}
	if err := json.Unmarshal([]byte(row.TargetSelector), &d.Selector); err != nil {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: stored selector is not valid", runbook.ErrInvalidInput)
	}
	if len(d.Parameters) == 0 {
		d.Parameters = nil
	}
	return d, nil
}

func (r *Repository) metadata(d runbook.StoredDefinition, op oplog.OpType) oplog.Metadata {
	return oplog.Metadata{
		"resource-public-id": []string{d.Id},
		"resource-type":      []string{"runbook definition"},
		"op-type":            []string{op.String()},
		"scope-id":           []string{d.ScopeId},
	}
}

// mapWriteErr turns database errors into the fixed repository errors. The
// original error is deliberately not wrapped: it can echo column values.
func mapWriteErr(op string, err error) error {
	switch {
	case berrors.IsUniqueError(err):
		return runbook.ErrAlreadyExists
	case strings.Contains(err.Error(), "foreign key constraint"):
		return fmt.Errorf("%w: unknown scope", runbook.ErrInvalidInput)
	case berrors.IsCheckConstraintError(err), berrors.IsNotNullError(err):
		return fmt.Errorf("%w: rejected by the database", runbook.ErrInvalidInput)
	}
	return fmt.Errorf("%s: database error", op)
}

// Create implements runbook.Repository.
func (r *Repository) Create(ctx context.Context, d runbook.StoredDefinition) (runbook.StoredDefinition, error) {
	const op = "runbook.db.Create"
	if err := ctx.Err(); err != nil {
		return runbook.StoredDefinition{}, err
	}
	if d.Version != 0 {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: version must be zero", runbook.ErrInvalidInput)
	}
	if err := d.Validate(); err != nil {
		return runbook.StoredDefinition{}, err
	}
	row, err := toRow(d)
	if err != nil {
		return runbook.StoredDefinition{}, err
	}
	wrapper, err := r.kms.GetWrapper(ctx, d.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return runbook.StoredDefinition{}, fmt.Errorf("%s: unable to get oplog wrapper", op)
	}
	md := r.metadata(d, oplog.OpType_OP_TYPE_CREATE)
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		return w.Create(ctx, row.clone(), db.WithOplog(wrapper, md))
	})
	if err != nil {
		return runbook.StoredDefinition{}, mapWriteErr(op, err)
	}
	return r.Get(ctx, d.Id)
}

// Get implements runbook.Repository.
func (r *Repository) Get(ctx context.Context, id string) (runbook.StoredDefinition, error) {
	const op = "runbook.db.Get"
	if err := ctx.Err(); err != nil {
		return runbook.StoredDefinition{}, err
	}
	if id == "" {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: id required", runbook.ErrInvalidInput)
	}
	row := allocRow()
	row.PublicId = id
	if err := r.reader.LookupById(ctx, row); err != nil {
		if berrors.IsNotFoundError(err) {
			return runbook.StoredDefinition{}, runbook.ErrNotFound
		}
		return runbook.StoredDefinition{}, fmt.Errorf("%s: database error", op)
	}
	return fromRow(row)
}

// List implements runbook.Repository. Only definitions of scopeID are
// returned, ordered by name then id.
func (r *Repository) List(ctx context.Context, scopeID string) ([]runbook.StoredDefinition, error) {
	const op = "runbook.db.List"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scopeID == "" {
		return nil, fmt.Errorf("%w: scope id required", runbook.ErrInvalidInput)
	}
	var rows []*dbRow
	if err := r.reader.SearchWhere(ctx, &rows, "scope_id = ?", []any{scopeID}, db.WithOrder("name, public_id")); err != nil {
		return nil, fmt.Errorf("%s: database error", op)
	}
	out := make([]runbook.StoredDefinition, 0, len(rows))
	for _, row := range rows {
		d, err := fromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// Update implements runbook.Repository. The write only succeeds when
// d.Version equals the stored version.
func (r *Repository) Update(ctx context.Context, d runbook.StoredDefinition) (runbook.StoredDefinition, error) {
	const op = "runbook.db.Update"
	if err := ctx.Err(); err != nil {
		return runbook.StoredDefinition{}, err
	}
	if err := d.Validate(); err != nil {
		return runbook.StoredDefinition{}, err
	}
	if d.Version == 0 {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: version required", runbook.ErrInvalidInput)
	}
	cur, err := r.Get(ctx, d.Id)
	if err != nil {
		return runbook.StoredDefinition{}, err
	}
	if cur.ScopeId != d.ScopeId {
		return runbook.StoredDefinition{}, fmt.Errorf("%w: scope id is immutable", runbook.ErrInvalidInput)
	}
	row, err := toRow(d)
	if err != nil {
		return runbook.StoredDefinition{}, err
	}
	mask := []string{"Name", "Interpreter", "SourceCommitSha", "ScriptPath", "ScriptSha256", "Parameters", "TargetSelector"}
	var nulls []string
	if d.Description == "" {
		nulls = append(nulls, "Description")
	} else {
		mask = append(mask, "Description")
	}
	wrapper, err := r.kms.GetWrapper(ctx, d.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return runbook.StoredDefinition{}, fmt.Errorf("%s: unable to get oplog wrapper", op)
	}
	md := r.metadata(d, oplog.OpType_OP_TYPE_UPDATE)
	version := d.Version
	var rowsUpdated int
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		var uerr error
		rowsUpdated, uerr = w.Update(ctx, row.clone(), mask, nulls, db.WithOplog(wrapper, md), db.WithVersion(&version))
		return uerr
	})
	if err != nil {
		if berrors.IsNotFoundError(err) {
			return runbook.StoredDefinition{}, r.staleOrMissing(ctx, d.Id)
		}
		return runbook.StoredDefinition{}, mapWriteErr(op, err)
	}
	if rowsUpdated == 0 {
		return runbook.StoredDefinition{}, r.staleOrMissing(ctx, d.Id)
	}
	return r.Get(ctx, d.Id)
}

// staleOrMissing reports why a versioned update touched no row.
func (r *Repository) staleOrMissing(ctx context.Context, id string) error {
	if _, err := r.Get(ctx, id); err != nil {
		return err
	}
	return runbook.ErrVersionConflict
}

// Delete implements runbook.Repository.
func (r *Repository) Delete(ctx context.Context, id string) error {
	const op = "runbook.db.Delete"
	if err := ctx.Err(); err != nil {
		return err
	}
	cur, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	wrapper, err := r.kms.GetWrapper(ctx, cur.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return fmt.Errorf("%s: unable to get oplog wrapper", op)
	}
	row := allocRow()
	row.PublicId = id
	md := r.metadata(cur, oplog.OpType_OP_TYPE_DELETE)
	var n int
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		var derr error
		n, derr = w.Delete(ctx, row, db.WithOplog(wrapper, md))
		return derr
	})
	if err != nil {
		return fmt.Errorf("%s: database error", op)
	}
	if n == 0 {
		return runbook.ErrNotFound
	}
	return nil
}
