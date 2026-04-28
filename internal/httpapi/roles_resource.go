package httpapi

import (
	"context"
	"errors"
	"strings"

	"github.com/arcgolabs/authx"
	"github.com/arcgolabs/httpx"
	iamservice "github.com/arcgolabs/arcgo-rbac-template/internal/iam/application/service"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type RolesResource struct {
	engine *authx.Engine
	svc    iamservice.RolesService
}

func (e *RolesResource) FiberBinding() FiberBinding {
	return FiberBinding{
		Prefix:  "/api/roles",
		Handler: requirePermissionFiber(e.engine, "roles:read", "/roles"),
	}
}

func (e *RolesResource) EndpointSpec() httpx.EndpointSpec {
	return httpx.EndpointSpec{
		Prefix:        "/api/roles",
		Tags:          httpx.Tags("roles"),
		SummaryPrefix: "Roles",
		Description:   "Roles resource",
	}
}

type rolesListInput struct {
	ID       string `query:"id"`
	Page     int64  `query:"page"`
	PageSize int64  `query:"pageSize"`
	Q        string `query:"q"`
	Sort     string `query:"sort"`
	Order    string `query:"order"`
	NameLike string `query:"name_like"`
}

func (e *RolesResource) Register(registrar httpx.Registrar) {
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
	httpx.MustGroupDelete(g, "", e.DeleteMany)
}

func (e *RolesResource) ListOrGetMany(ctx context.Context, in *rolesListInput) (*PageResponse[RoleDTO], error) {
	if strings.TrimSpace(in.ID) != "" {
		items := e.getMany(ctx, splitIDs(in.ID))
		pageSize := int64(len(items))
		return &PageResponse[RoleDTO]{Items: items, Total: pageSize, Page: 1, PageSize: pageSize}, nil
	}
	return e.List(ctx, in)
}

func (e *RolesResource) List(ctx context.Context, in *rolesListInput) (*PageResponse[RoleDTO], error) {
	if in.Page <= 0 || in.PageSize <= 0 {
		return nil, httpx.NewError(400, "validation", errors.New("page and pageSize are required"))
	}
	page, err := e.svc.List(ctx, domain.RolesListQuery{
		PageParams: domain.PageParams{Page: in.Page, PageSize: in.PageSize},
		Q:         strings.TrimSpace(in.Q),
		Sort:      strings.TrimSpace(in.Sort),
		Order:     domain.NormalizeOrder(in.Order),
		NameLike:  strings.TrimSpace(in.NameLike),
	})
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}

	items := make([]RoleDTO, 0, len(page.Items))
	for _, r := range page.Items {
		_, gids, gerr := e.svc.Get(ctx, r.ID)
		if gerr != nil && !errors.Is(gerr, domain.ErrNotFound) {
			return nil, httpx.NewError(500, "unknown", gerr)
		}
		outGids := make([]string, 0, len(gids))
		for _, gid := range gids {
			outGids = append(outGids, string(gid))
		}
		items = append(items, RoleDTO{
			ID:                 string(r.ID),
			Name:               r.Name,
			Description:        r.Description,
			PermissionGroupIDs: outGids,
			CreatedAt:          unixMilliToRFC3339(r.CreatedAt),
		})
	}

	return &PageResponse[RoleDTO]{Items: items, Total: page.Total, Page: page.Page, PageSize: page.PageSize}, nil
}

func (e *RolesResource) Get(ctx context.Context, in *userIDPath) (*RoleDTO, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	r, gids, err := e.svc.Get(ctx, domain.RoleID(id))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	outGids := make([]string, 0, len(gids))
	for _, gid := range gids {
		outGids = append(outGids, string(gid))
	}
	return &RoleDTO{
		ID:                 string(r.ID),
		Name:               r.Name,
		Description:        r.Description,
		PermissionGroupIDs: outGids,
		CreatedAt:          unixMilliToRFC3339(r.CreatedAt),
	}, nil
}

func (e *RolesResource) GetByID(ctx context.Context, in *userIDPath) (*RoleDTO, error) {
	return e.Get(ctx, in)
}

type createRoleInput struct {
	Body RoleDTO `json:"body"`
}

func (e *RolesResource) Create(ctx context.Context, in *createRoleInput) (*RoleDTO, error) {
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	r := in.Body
	r.ID = strings.TrimSpace(r.ID)
	r.Name = strings.TrimSpace(r.Name)
	if r.ID == "" || r.Name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	desc := strings.TrimSpace(r.Description)
	now := nowUnixMilli()
	groupIDs := make([]domain.PermissionGroupID, 0, len(r.PermissionGroupIDs))
	for _, gid := range r.PermissionGroupIDs {
		gid = strings.TrimSpace(gid)
		if gid != "" {
			groupIDs = append(groupIDs, domain.PermissionGroupID(gid))
		}
	}
	created, outGroups, err := e.svc.Create(ctx, domain.Role{
		ID:          domain.RoleID(r.ID),
		Name:        r.Name,
		Description: desc,
		CreatedAt:   now,
	}, groupIDs)
	if err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	r.ID = string(created.ID)
	r.Name = created.Name
	r.Description = created.Description
	r.CreatedAt = unixMilliToRFC3339(created.CreatedAt)
	r.PermissionGroupIDs = make([]string, 0, len(outGroups))
	for _, gid := range outGroups {
		r.PermissionGroupIDs = append(r.PermissionGroupIDs, string(gid))
	}
	return &r, nil
}

type updateRoleInput struct {
	ID   string `path:"id"`
	Body RoleDTO `json:"body"`
}

func (e *RolesResource) Update(ctx context.Context, in *updateRoleInput) (*RoleDTO, error) {
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	name := strings.TrimSpace(in.Body.Name)
	desc := strings.TrimSpace(in.Body.Description)
	if id == "" || name == "" {
		return nil, httpx.NewError(422, "validation")
	}
	groupIDs := make([]domain.PermissionGroupID, 0, len(in.Body.PermissionGroupIDs))
	for _, gid := range in.Body.PermissionGroupIDs {
		gid = strings.TrimSpace(gid)
		if gid != "" {
			groupIDs = append(groupIDs, domain.PermissionGroupID(gid))
		}
	}
	updated, outGroups, err := e.svc.Update(ctx, domain.Role{ID: domain.RoleID(id), Name: name, Description: desc}, groupIDs)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, httpx.NewError(404, "not_found", err)
		}
		return nil, httpx.NewError(500, "unknown", err)
	}
	dtoGroups := make([]string, 0, len(outGroups))
	for _, gid := range outGroups {
		dtoGroups = append(dtoGroups, string(gid))
	}
	return &RoleDTO{
		ID:                 string(updated.ID),
		Name:               updated.Name,
		Description:        updated.Description,
		PermissionGroupIDs: dtoGroups,
		CreatedAt:          unixMilliToRFC3339(updated.CreatedAt),
	}, nil
}

func (e *RolesResource) UpdateByID(ctx context.Context, in *updateRoleInput) (*RoleDTO, error) {
	return e.Update(ctx, in)
}

func (e *RolesResource) Delete(ctx context.Context, in *userIDPath) (*struct{}, error) {
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, httpx.NewError(422, "validation")
	}
	if err := e.svc.Delete(ctx, domain.RoleID(id)); err != nil {
		return nil, httpx.NewError(500, "unknown", err)
	}
	return &struct{}{}, nil
}

func (e *RolesResource) DeleteByID(ctx context.Context, in *userIDPath) (*struct{}, error) {
	return e.Delete(ctx, in)
}

// NOTE: group link operations moved into domain repository/service layer.
