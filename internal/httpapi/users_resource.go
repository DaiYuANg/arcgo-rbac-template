package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/httpx"
	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type UsersResource struct {
	engine *authx.Engine
	svc    iamservice.UsersService
	cacheTTL    time.Duration
}

func (e *UsersResource) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/users",
		Handler: requirePermissionFiber(e.engine, "users:read", "/users"),
	}
}

func (e *UsersResource) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/users",
		Tags:          httpx.Tags("users"),
		SummaryPrefix: "Users",
		Description:   "Users resource",
	}
}

type usersListInput struct {
	Page     int64  `minimum:"1"        query:"page"`
	PageSize int64  `minimum:"1"        query:"pageSize"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
	EmailLike string `query:"email_like"`
}

func (e *UsersResource) Register(registrar httpx.Registrar) {
	g := registrar.Scope()
	httpx.MustAuto(g,
		httpx.Auto(e.ListOrGetMany),
		httpx.Auto(e.GetByID),
		httpx.Auto(e.Create),
		httpx.Auto(e.UpdateByID),
		httpx.Auto(e.DeleteByID),
	)
	httpx.MustGroupPost(g, "/bulk", e.CreateMany)
	httpx.MustGroupPatch(g, "/bulk", e.UpdateMany)
	httpx.MustGroupDelete(g, "", e.DeleteManyOrGetMany)
}

func (e *UsersResource) List(ctx context.Context, in *usersListInput) (*PageResponse[UserDTO], error) {
	if in.Page <= 0 || in.PageSize <= 0 {
		return nil, httpx.NewError(400, "validation", errors.New("page and pageSize are required"))
	}
	page, err := e.svc.List(ctx, domain.UsersListQuery{
		PageParams: domain.PageParams{Page: in.Page, PageSize: in.PageSize},
		Q:         strings.TrimSpace(in.Q),
		Sort:      strings.TrimSpace(in.Sort),
		Order:     domain.NormalizeOrder(in.Order),
		NameLike:  strings.TrimSpace(in.NameLike),
		EmailLike: strings.TrimSpace(in.EmailLike),
	})
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	items := make([]UserDTO, 0, len(page.Items))
	for _, u := range page.Items {
		items = append(items, UserDTO{
			ID:        string(u.ID),
			Email:     u.Email,
			Name:      u.Name,
			CreatedAt: unixMilliToRFC3339(u.CreatedAt),
		})
	}
	return &PageResponse[UserDTO]{Items: items, Total: page.Total, Page: page.Page, PageSize: page.PageSize}, nil
}

type userIDPath struct {
	ID string `path:"id"`
}

func (e *UsersResource) Get(ctx context.Context, in *userIDPath) (*UserDTO, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(400, "validation")
	}
	u, roleIDs, err := e.svc.Get(ctx, domain.UserID(id))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	outRoles := make([]string, 0, len(roleIDs))
	for _, rid := range roleIDs {
		outRoles = append(outRoles, string(rid))
	}
	return &UserDTO{
		ID:        string(u.ID),
		Email:     u.Email,
		Name:      u.Name,
		RoleIDs:   outRoles,
		CreatedAt: unixMilliToRFC3339(u.CreatedAt),
	}, nil
}

func (e *UsersResource) GetByID(ctx context.Context, in *userIDPath) (*UserDTO, error) {
	return e.Get(ctx, in)
}

type createUserInput struct {
	Body UserDTO `json:"body"`
}

func (e *UsersResource) Create(ctx context.Context, in *createUserInput) (*UserDTO, error) {
	u := in.Body
	if err := normalizeUserCreate(&u); err != nil {
		return nil, err
	}
	return e.createUser(ctx, u)
}

func normalizeUserCreate(u *UserDTO) error {
	if u == nil {
		return httpx.NewError(422, "validation")
	}
	u.ID = strings.TrimSpace(u.ID)
	u.Email = strings.TrimSpace(u.Email)
	u.Name = strings.TrimSpace(u.Name)
	if u.Email == "" || u.Name == "" {
		return httpx.NewError(422, "validation")
	}
	return nil
}

func (e *UsersResource) createUser(ctx context.Context, u UserDTO) (*UserDTO, error) {
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	roleIDs := make([]domain.RoleID, 0, len(u.RoleIDs))
	for _, rid := range u.RoleIDs {
		rid = strings.TrimSpace(rid)
		if rid != "" {
			roleIDs = append(roleIDs, domain.RoleID(rid))
		}
	}
	created, outRoles, err := e.svc.Create(ctx, domain.User{
		ID:        domain.UserID(u.ID),
		Email:     u.Email,
		Name:      u.Name,
		CreatedAt: now,
	}, roleIDs)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	u.ID = string(created.ID)
	u.CreatedAt = unixMilliToRFC3339(created.CreatedAt)
	u.RoleIDs = make([]string, 0, len(outRoles))
	for _, rid := range outRoles {
		u.RoleIDs = append(u.RoleIDs, string(rid))
	}
	return &u, nil
}



type createUsersBulkInput struct {
	Body BulkItems[UserDTO] `json:"body"`
}

func (e *UsersResource) CreateMany(ctx context.Context, in *createUsersBulkInput) (*[]UserDTO, error) {
	out := make([]UserDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createUserInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, *created)
	}
	return &out, nil
}

type updateUserInput struct {
	ID   string  `path:"id"`
	Body UserDTO `json:"body"`
}

func (e *UsersResource) Update(ctx context.Context, in *updateUserInput) (*UserDTO, error) {
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	email := strings.TrimSpace(in.Body.Email)
	name := strings.TrimSpace(in.Body.Name)
	if email == "" || name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	roleIDs := make([]domain.RoleID, 0, len(in.Body.RoleIDs))
	for _, rid := range in.Body.RoleIDs {
		rid = strings.TrimSpace(rid)
		if rid != "" {
			roleIDs = append(roleIDs, domain.RoleID(rid))
		}
	}
	updated, outRoles, err := e.svc.Update(ctx, domain.User{ID: domain.UserID(id), Email: email, Name: name}, roleIDs)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	dtoRoles := make([]string, 0, len(outRoles))
	for _, rid := range outRoles {
		dtoRoles = append(dtoRoles, string(rid))
	}
	return &UserDTO{
		ID:        string(updated.ID),
		Email:     updated.Email,
		Name:      updated.Name,
		RoleIDs:   dtoRoles,
		CreatedAt: unixMilliToRFC3339(updated.CreatedAt),
	}, nil
}

func (e *UsersResource) UpdateByID(ctx context.Context, in *updateUserInput) (*UserDTO, error) {
	return e.Update(ctx, in)
}

type updateUsersBulkInput struct {
	ID   string  `query:"id"`
	Body UserDTO `json:"body"`
}

func (e *UsersResource) UpdateMany(ctx context.Context, in *updateUsersBulkInput) (*[]UserDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		dto, err := e.Update(ctx, &updateUserInput{ID: id, Body: in.Body})
		if err != nil {
			return nil, err
		}
		out = append(out, *dto)
	}
	return &out, nil
}

func (e *UsersResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	if err := e.svc.Delete(ctx, domain.UserID(id)); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *UsersResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
}

type idsQuery struct {
	ID string `query:"id"`
}

type usersListOrManyInput struct {
	idsQuery
	usersListInput
}

func (e *UsersResource) ListOrGetMany(ctx context.Context, in *usersListOrManyInput) (*PageResponse[UserDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items, err := e.GetMany(ctx, &idsQuery{ID: in.ID})
		if err != nil {
			return nil, err
		}
		pageSize := int64(0)
		if items != nil {
			pageSize = int64(len(*items))
		}
		return &PageResponse[UserDTO]{
			Items:    loOrEmpty(items),
			Total:    pageSize,
			Page:     1,
			PageSize: pageSize,
		}, nil
	}
	return e.List(ctx, &in.usersListInput)
}

func loOrEmpty(items *[]UserDTO) []UserDTO {
	if items == nil {
		return []UserDTO{}
	}
	return *items
}

func (e *UsersResource) DeleteManyOrGetMany(ctx context.Context, in *idsQuery) (*[]UserDTO, error) {
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	// This handler is only used for DELETE many (method-bound), but httpx's typed inputs are shared.
	// We still keep it returning []UserDTO to match contract when needed.
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

func (e *UsersResource) GetMany(ctx context.Context, in *idsQuery) (*[]UserDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err != nil {
			continue
		}
		out = append(out, *item)
	}
	return &out, nil
}

func splitIDs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// NOTE: role link operations moved into domain repository/service layer.

