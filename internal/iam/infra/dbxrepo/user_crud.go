package dbxrepo

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/dbx"
	"github.com/arcgolabs/dbx/mapper"
	"github.com/arcgolabs/dbx/querydsl"
	"github.com/arcgolabs/dbx/repository"
)

var userListOrders = map[string]func(bool) querydsl.Order{
	"id": func(d bool) querydsl.Order {
		if d {
			return Users.ID.Desc()
		}
		return Users.ID.Asc()
	},
	"email": func(d bool) querydsl.Order {
		if d {
			return Users.Email.Desc()
		}
		return Users.Email.Asc()
	},
	"name": func(d bool) querydsl.Order {
		if d {
			return Users.Name.Desc()
		}
		return Users.Name.Asc()
	},
	"createdAt": func(d bool) querydsl.Order {
		if d {
			return Users.CreatedAt.Desc()
		}
		return Users.CreatedAt.Asc()
	},
}

func usersListPredicates(q domain.UsersListQuery) []querydsl.Predicate {
	preds := make([]querydsl.Predicate, 0, 4)
	if v := strings.TrimSpace(q.NameLike); v != "" {
		preds = append(preds, querydsl.Like(Users.Name, "%"+v+"%"))
	}
	if v := strings.TrimSpace(q.EmailLike); v != "" {
		preds = append(preds, querydsl.Like(Users.Email, "%"+v+"%"))
	}
	if v := strings.TrimSpace(q.Q); v != "" {
		preds = append(preds, querydsl.Or(
			querydsl.Like(Users.Name, "%"+v+"%"),
			querydsl.Like(Users.Email, "%"+v+"%"),
		))
	}
	return preds
}

func (r *UserRepo) Get(ctx context.Context, userID domain.UserID) (domain.User, error) {
	id := strings.TrimSpace(string(userID))
	if id == "" {
		return domain.User{}, domain.ErrNotFound
	}
	type row struct {
		ID        string `dbx:"id"`
		Email     string `dbx:"email"`
		Name      string `dbx:"name"`
		CreatedAt int64  `dbx:"created_at"`
	}
	q := querydsl.
		Select(Users.ID, Users.Email, Users.Name, Users.CreatedAt).
		From(Users).
		Where(Users.ID.Eq(id)).
		Limit(1)
	first, err := queryOne[row](ctx, r.core, q, "user get")
	if err != nil {
		return domain.User{}, err
	}
	return domain.User{
		ID:        domain.UserID(first.ID),
		Email:     first.Email,
		Name:      first.Name,
		CreatedAt: first.CreatedAt,
	}, nil
}

func (r *UserRepo) List(ctx context.Context, q domain.UsersListQuery) (domain.Page[domain.User], error) {
	where := predicatesAnd(usersListPredicates(q))

	countQuery := querydsl.
		Select(querydsl.CountAll().As("total")).
		From(Users).
		Where(where)
	total, err := countTotal(ctx, r.core, countQuery)
	if err != nil {
		return domain.Page[domain.User]{}, fmt.Errorf("user list count: %w", err)
	}

	desc := q.Order == domain.SortDesc
	ord, oerr := listOrderBy(q.Sort, desc, userListOrders)
	if oerr != nil {
		return domain.Page[domain.User]{}, fmt.Errorf("user list: %w", oerr)
	}

	type row struct {
		ID        string `dbx:"id"`
		Email     string `dbx:"email"`
		Name      string `dbx:"name"`
		CreatedAt int64  `dbx:"created_at"`
	}
	listQuery := querydsl.
		Select(Users.ID, Users.Email, Users.Name, Users.CreatedAt).
		From(Users).
		Where(where).
		PageBy(int(q.Page), int(q.PageSize)).
		OrderBy(ord)

	items, err := dbx.QueryAll(ctx, r.core, listQuery, mapper.MustStructMapper[row]())
	if err != nil {
		return domain.Page[domain.User]{}, fmt.Errorf("user list: %w", err)
	}
	out := make([]domain.User, 0, items.Len())
	if items != nil {
		items.Range(func(_ int, r row) bool {
			out = append(out, domain.User{
				ID:        domain.UserID(r.ID),
				Email:     r.Email,
				Name:      r.Name,
				CreatedAt: r.CreatedAt,
			})
			return true
		})
	}
	return domain.Page[domain.User]{Items: out, Total: total, Page: q.Page, PageSize: q.PageSize}, nil
}

func (r *UserRepo) Create(ctx context.Context, u domain.User) (domain.User, error) {
	ent := User{
		ID:        strings.TrimSpace(string(u.ID)),
		Email:     strings.TrimSpace(u.Email),
		Name:      strings.TrimSpace(u.Name),
		CreatedAt: u.CreatedAt,
	}
	if err := repository.New[User](r.core, Users).Create(ctx, &ent); err != nil {
		return domain.User{}, fmt.Errorf("user create: %w", err)
	}
	return domain.User{ID: domain.UserID(ent.ID), Email: ent.Email, Name: ent.Name, CreatedAt: ent.CreatedAt}, nil
}

func (r *UserRepo) Update(ctx context.Context, u domain.User) (domain.User, error) {
	id := strings.TrimSpace(string(u.ID))
	if id == "" {
		return domain.User{}, domain.ErrNotFound
	}
	upd := querydsl.
		Update(Users).
		Set(
			Users.Email.Set(strings.TrimSpace(u.Email)),
			Users.Name.Set(strings.TrimSpace(u.Name)),
		).
		Where(Users.ID.Eq(id))
	if _, err := dbx.Exec(ctx, r.core, upd); err != nil {
		return domain.User{}, fmt.Errorf("user update: %w", err)
	}
	return r.Get(ctx, domain.UserID(id))
}

func (r *UserRepo) Delete(ctx context.Context, userID domain.UserID) error {
	id := strings.TrimSpace(string(userID))
	if id == "" {
		return nil
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(UserRoles).Where(UserRoles.UserID.Eq(id))); err != nil {
		return fmt.Errorf("user delete links: %w", err)
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(Users).Where(Users.ID.Eq(id))); err != nil {
		return fmt.Errorf("user delete: %w", err)
	}
	return nil
}

func (r *UserRepo) ReplaceRoles(ctx context.Context, userID domain.UserID, roleIDs []domain.RoleID) error {
	id := strings.TrimSpace(string(userID))
	if id == "" {
		return nil
	}
	if roleIDs == nil {
		return nil
	}
	if _, err := dbx.Exec(ctx, r.core, querydsl.DeleteFrom(UserRoles).Where(UserRoles.UserID.Eq(id))); err != nil {
		return fmt.Errorf("user replace roles delete: %w", err)
	}
	for _, rid := range roleIDs {
		v := strings.TrimSpace(string(rid))
		if v == "" {
			continue
		}
		ins := querydsl.
			InsertInto(UserRoles).
			Values(UserRoles.UserID.Set(id), UserRoles.RoleID.Set(v)).
			OnConflict(UserRoles.UserID, UserRoles.RoleID).
			DoNothing()
		if _, err := dbx.Exec(ctx, r.core, ins); err != nil {
			return fmt.Errorf("user replace roles insert: %w", err)
		}
	}
	return nil
}
