// Copyright Boundary Unlimited contributors 2026
// SPDX-License-Identifier: MIT

package accessrequest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/accessrequest/store"
	"github.com/hashicorp/boundary/internal/db"
	berrors "github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// ErrNotImplemented is returned by the DBRepository methods that later slices
// of issue #261 implement. Nothing is stored or changed when it is returned.
var ErrNotImplemented = errors.New("accessrequest: not implemented")

// dbRow is the gorm and oplog model for the access_request table.
type dbRow struct {
	*store.AccessRequest
	tableName string `gorm:"-"`
}

func allocRow() *dbRow { return &dbRow{AccessRequest: &store.AccessRequest{}} }

// TableName implements oplog.ReplayableMessage.
func (r *dbRow) TableName() string {
	if r.tableName != "" {
		return r.tableName
	}
	return "access_request"
}

// SetTableName implements oplog.ReplayableMessage.
func (r *dbRow) SetTableName(name string) { r.tableName = name }

func (r *dbRow) clone() *dbRow {
	return &dbRow{AccessRequest: proto.Clone(r.AccessRequest).(*store.AccessRequest)}
}

// DBRepository is the database-backed Repository, written through the oplog.
// It implements Create, Get, List and ListActive; Update returns
// ErrNotImplemented until the next slice of #261 lands. Unlike MemRepository
// it is strict: Create only stores a pending request, so the database always
// starts a request in the pending state and the approval fields are only set
// by a later transition.
type DBRepository struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms
	clock  func() time.Time
}

var (
	_ Repository   = (*DBRepository)(nil)
	_ ActiveLister = (*DBRepository)(nil)
)

// DBOption configures a DBRepository.
type DBOption func(*DBRepository)

// WithClock sets the clock used by ListActive. It is the only source of time
// for expiry decisions: the database's now() is never consulted. A nil clock
// is ignored and time.Now is used.
func WithClock(clock func() time.Time) DBOption {
	return func(d *DBRepository) { d.clock = clock }
}

// NewDBRepository returns a DBRepository. All arguments are required.
func NewDBRepository(ctx context.Context, r db.Reader, w db.Writer, k *kms.Kms, opts ...DBOption) (*DBRepository, error) {
	switch {
	case r == nil:
		return nil, fmt.Errorf("%w: nil db reader", ErrInvalidInput)
	case w == nil:
		return nil, fmt.Errorf("%w: nil db writer", ErrInvalidInput)
	case k == nil:
		return nil, fmt.Errorf("%w: nil kms", ErrInvalidInput)
	}
	d := &DBRepository{reader: r, writer: w, kms: k}
	for _, o := range opts {
		o(d)
	}
	return d, nil
}

// Create implements Repository. The request must be pending with no decision
// or expiry recorded, so a request can never be created already approved. The
// grant hash is always computed from the grants; a caller supplied one that
// differs is rejected.
func (d *DBRepository) Create(ctx context.Context, r Request) (Request, error) {
	const op = "accessrequest.(DBRepository).Create"
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	switch {
	case r.Id == "":
		return Request{}, fmt.Errorf("%w: id required", ErrInvalidInput)
	case r.Version != 0:
		return Request{}, fmt.Errorf("%w: version must be zero", ErrInvalidInput)
	case r.ScopeId == "" || r.RequesterId == "":
		return Request{}, fmt.Errorf("%w: scope and requester required", ErrInvalidInput)
	case r.State != StatePending:
		return Request{}, fmt.Errorf("%w: a new request must be pending", ErrInvalidInput)
	case !r.ExpiresAt.IsZero():
		// An expiry is only set on approval, and one in the past would be
		// an already-expired grant.
		return Request{}, fmt.Errorf("%w: a pending request has no expiry", ErrInvalidInput)
	case r.DecidedBy != "" || !r.DecidedAt.IsZero():
		return Request{}, fmt.Errorf("%w: a pending request has no decision", ErrInvalidInput)
	case len(r.Grants) == 0 || len(r.Grants) > DefaultMaxGrants:
		return Request{}, fmt.Errorf("%w: grants must have 1 to %d entries", ErrInvalidInput, DefaultMaxGrants)
	case strings.TrimSpace(r.Justification) == "" || len(r.Justification) > DefaultMaxJustification:
		return Request{}, fmt.Errorf("%w: justification must be 1 to %d bytes", ErrInvalidInput, DefaultMaxJustification)
	case r.Duration < time.Second || r.Duration%time.Second != 0 || r.Duration > time.Duration(1<<31-1)*time.Second:
		return Request{}, fmt.Errorf("%w: duration must be a positive whole number of seconds", ErrInvalidInput)
	}
	for _, g := range r.Grants {
		if strings.TrimSpace(g) == "" {
			return Request{}, fmt.Errorf("%w: empty grant", ErrInvalidInput)
		}
	}
	hash := GrantHash(r.Grants)
	if r.GrantHash != "" && r.GrantHash != hash {
		return Request{}, fmt.Errorf("%w: grant hash does not match grants", ErrInvalidInput)
	}

	wrapper, err := d.kms.GetWrapper(ctx, r.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return Request{}, fmt.Errorf("%s: unable to get oplog wrapper: %w", op, err)
	}
	row := allocRow()
	row.PublicId = r.Id
	row.ScopeId = r.ScopeId
	row.RequesterId = r.RequesterId
	row.Grants = encodeTextArray(r.Grants)
	row.GrantHash = hash
	row.Justification = r.Justification
	row.TtlSeconds = int32(r.Duration / time.Second)
	// state and version are left to the database defaults (pending, 1).

	metadata := oplog.Metadata{
		"resource-public-id": []string{r.Id},
		"resource-type":      []string{"access request"},
		"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		"scope-id":           []string{r.ScopeId},
	}
	_, err = d.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(_ db.Reader, w db.Writer) error {
		return w.Create(ctx, row.clone(), db.WithOplog(wrapper, metadata))
	})
	if err != nil {
		switch {
		case berrors.IsUniqueError(err):
			return Request{}, ErrAlreadyExists
		case berrors.IsNotFoundError(err), strings.Contains(err.Error(), "foreign key constraint"):
			return Request{}, fmt.Errorf("%w: unknown scope or requester", ErrInvalidInput)
		case berrors.IsCheckConstraintError(err), berrors.IsNotNullError(err):
			return Request{}, fmt.Errorf("%w: rejected by the database", ErrInvalidInput)
		}
		return Request{}, fmt.Errorf("%s: %w", op, err)
	}
	return d.Get(ctx, r.Id)
}

// Get implements Repository.
func (d *DBRepository) Get(ctx context.Context, id string) (Request, error) {
	const op = "accessrequest.(DBRepository).Get"
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	if id == "" {
		return Request{}, fmt.Errorf("%w: id required", ErrInvalidInput)
	}
	row := allocRow()
	row.PublicId = id
	if err := d.reader.LookupById(ctx, row); err != nil {
		if berrors.IsNotFoundError(err) {
			return Request{}, ErrNotFound
		}
		return Request{}, fmt.Errorf("%s: %w", op, err)
	}
	return fromRow(row)
}

// List implements Repository. Results are ordered by creation time then id.
// DecidedBy and DecidedAt of an approved or denied request come from its
// latest matching access_request_approval row; they are zero when no such row
// exists, which makes the overlay drop an approved request as malformed.
func (d *DBRepository) List(ctx context.Context, f ListFilter) ([]Request, error) {
	return d.list(ctx, f, nil)
}

// ListActive implements ActiveLister. The expiry comparison is made against
// the repository's clock, passed to the query as a parameter, never now().
func (d *DBRepository) ListActive(ctx context.Context, f ListFilter) ([]Request, error) {
	f.States = intersectApproved(f.States)
	if f.States == nil {
		return nil, ctx.Err()
	}
	now := time.Now()
	if d.clock != nil {
		now = d.clock()
	}
	return d.list(ctx, f, &now)
}

const listSelect = `
select r.public_id, r.scope_id, r.requester_id, r.grants::text, r.grant_hash,
       r.justification, r.state, r.ttl_seconds, r.create_time, r.expiry_time,
       r.version, a.approver_id, a.create_time
  from access_request r
  left join lateral (
        select approver_id, create_time
          from access_request_approval
         where request_id = r.public_id and decision = r.state
         order by create_time desc, approver_id desc
         limit 1) a on true`

func (d *DBRepository) list(ctx context.Context, f ListFilter, activeAt *time.Time) ([]Request, error) {
	const op = "accessrequest.(DBRepository).List"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var where []string
	var args []any
	if f.ScopeId != "" {
		where = append(where, "r.scope_id = ?")
		args = append(args, f.ScopeId)
	}
	if f.RequesterId != "" {
		where = append(where, "r.requester_id = ?")
		args = append(args, f.RequesterId)
	}
	if f.ApproverId != "" {
		where = append(where, "a.approver_id = ?")
		args = append(args, f.ApproverId)
	}
	if len(f.States) > 0 {
		ph := make([]string, 0, len(f.States))
		for _, s := range f.States {
			if !s.valid() {
				return nil, fmt.Errorf("%w: unknown state %q", ErrInvalidState, string(s))
			}
			ph = append(ph, "?")
			args = append(args, string(s))
		}
		where = append(where, "r.state in ("+strings.Join(ph, ",")+")")
	}
	if activeAt != nil {
		where = append(where, "r.state = 'approved'", "r.expiry_time is not null", "r.expiry_time > ?")
		args = append(args, activeAt.UTC())
	}
	q := listSelect
	if len(where) > 0 {
		q += "\n where " + strings.Join(where, " and ")
	}
	q += "\n order by r.create_time, r.public_id"

	rows, err := d.reader.Query(ctx, q, args)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var (
			row                 = allocRow()
			grants              string
			requester, approver sql.NullString
			created             time.Time
			expiry, decided     sql.NullTime
		)
		if err := rows.Scan(&row.PublicId, &row.ScopeId, &requester, &grants, &row.GrantHash,
			&row.Justification, &row.State, &row.TtlSeconds, &created, &expiry,
			&row.Version, &approver, &decided); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		row.RequesterId = requester.String
		row.Grants = grants
		r, err := fromRow(row)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		r.CreatedAt = created
		if expiry.Valid {
			r.ExpiresAt = expiry.Time
		}
		r.DecidedBy = approver.String
		if decided.Valid {
			r.DecidedAt = decided.Time
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return out, nil
}

// Update implements Repository. Not implemented until slice 3 of #261.
func (d *DBRepository) Update(ctx context.Context, r Request) (Request, error) {
	return Request{}, ErrNotImplemented
}

func fromRow(row *dbRow) (Request, error) {
	grants, err := decodeTextArray(row.Grants)
	if err != nil {
		return Request{}, fmt.Errorf("%w: stored grants: %v", ErrInvalidInput, err)
	}
	st := State(row.State)
	if !st.valid() {
		return Request{}, fmt.Errorf("%w: stored state %q", ErrInvalidState, row.State)
	}
	r := Request{
		Id:            row.PublicId,
		RequesterId:   row.RequesterId,
		ScopeId:       row.ScopeId,
		Grants:        grants,
		Justification: row.Justification,
		Duration:      time.Duration(row.TtlSeconds) * time.Second,
		State:         st,
		GrantHash:     row.GrantHash,
		Version:       row.Version,
	}
	if row.CreateTime != nil {
		r.CreatedAt = row.CreateTime.AsTime()
	}
	if row.ExpiryTime != nil {
		r.ExpiresAt = row.ExpiryTime.AsTime()
	}
	return r, nil
}

// encodeTextArray renders values as a postgres text[] literal.
func encodeTextArray(vals []string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		for _, c := range v {
			if c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(c)
		}
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// decodeTextArray parses a postgres text[] literal, quoted or unquoted.
func decodeTextArray(s string) ([]string, error) {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, errors.New("not an array literal")
	}
	s = s[1 : len(s)-1]
	var out []string
	for i := 0; i < len(s); {
		var b strings.Builder
		if s[i] == '"' {
			i++
			closed := false
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				return nil, errors.New("unterminated quoted element")
			}
		} else {
			for i < len(s) && s[i] != ',' {
				b.WriteByte(s[i])
				i++
			}
		}
		out = append(out, b.String())
		if i < len(s) {
			if s[i] != ',' {
				return nil, errors.New("expected comma")
			}
			i++
			if i == len(s) {
				return nil, errors.New("trailing comma")
			}
		}
	}
	return out, nil
}
