package httpapi

import (
	"context"
	"strings"
)

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

type idsQuery struct {
	ID string `query:"id"`
}

func (e *UsersResource) ListOrGetMany(ctx context.Context, in *usersListInput) (*PageResponse[UserDTO], error) {
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
	return e.List(ctx, in)
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
