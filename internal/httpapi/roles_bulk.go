package httpapi

import "context"

type createRolesBulkInput struct {
	Body BulkItems[RoleDTO] `json:"body"`
}

func (e *RolesResource) CreateMany(ctx context.Context, in *createRolesBulkInput) (*[]RoleDTO, error) {
	out := make([]RoleDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createRoleInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, *created)
	}
	return &out, nil
}

type updateRolesBulkInput struct {
	ID   string  `query:"id"`
	Body RoleDTO `json:"body"`
}

func (e *RolesResource) UpdateMany(ctx context.Context, in *updateRolesBulkInput) (*[]RoleDTO, error) {
	ids := splitIDs(in.ID)
	out := make([]RoleDTO, 0, len(ids))
	for _, id := range ids {
		dto, err := e.Update(ctx, &updateRoleInput{ID: id, Body: in.Body})
		if err != nil {
			return nil, err
		}
		out = append(out, *dto)
	}
	return &out, nil
}

func (e *RolesResource) DeleteMany(ctx context.Context, in *idsQuery) (*[]RoleDTO, error) {
	if err := enforce(ctx, e.engine, "roles:write", "/roles"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]RoleDTO, 0, len(ids))
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

func (e *RolesResource) getMany(ctx context.Context, ids []string) []RoleDTO {
	out := []RoleDTO{}
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, *item)
		}
	}
	return out
}
