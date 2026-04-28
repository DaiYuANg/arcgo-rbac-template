package httpapi

import (
	"context"
	"strings"
)

type createUsersBulkInput struct {
	Body BulkItems[UserDTO] `json:"body"`
}

func (e *UsersResource) CreateMany(ctx context.Context, in *createUsersBulkInput) (*BulkResponse[UserDTO], error) {
	out := make([]UserDTO, 0, len(in.Body.Items))
	for _, item := range in.Body.Items {
		created, err := e.Create(ctx, &createUserInput{Body: item})
		if err != nil {
			return nil, err
		}
		out = append(out, created.Body)
	}
	return &BulkResponse[UserDTO]{Body: BulkPayload[UserDTO]{Items: out}}, nil
}

type updateUsersBulkInput struct {
	ID   string  `query:"id"`
	Body UserDTO `json:"body"`
}

func (e *UsersResource) UpdateMany(ctx context.Context, in *updateUsersBulkInput) (*BulkResponse[UserDTO], error) {
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		dto, err := e.Update(ctx, &updateUserInput{ID: id, Body: in.Body})
		if err != nil {
			return nil, err
		}
		out = append(out, dto.Body)
	}
	return &BulkResponse[UserDTO]{Body: BulkPayload[UserDTO]{Items: out}}, nil
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
		rowItems := []UserDTO(nil)
		if items != nil {
			rowItems = items.Body.Items
		}
		n := int64(len(rowItems))
		return &PageResponse[UserDTO]{
			Body: PagePayload[UserDTO]{
				Items:    rowItems,
				Total:    n,
				Page:     1,
				PageSize: n,
			},
		}, nil
	}
	return e.List(ctx, in)
}

func (e *UsersResource) DeleteManyOrGetMany(ctx context.Context, in *idsQuery) (*BulkResponse[UserDTO], error) {
	if err := enforce(ctx, e.engine, "users:write", "/users"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, item.Body)
		}
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
	}
	return &BulkResponse[UserDTO]{Body: BulkPayload[UserDTO]{Items: out}}, nil
}

func (e *UsersResource) GetMany(ctx context.Context, in *idsQuery) (*BulkResponse[UserDTO], error) {
	ids := splitIDs(in.ID)
	out := make([]UserDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err != nil {
			continue
		}
		out = append(out, item.Body)
	}
	return &BulkResponse[UserDTO]{Body: BulkPayload[UserDTO]{Items: out}}, nil
}
