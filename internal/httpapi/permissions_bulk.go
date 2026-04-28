package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
)

type updatePermBulkInput struct {
	ID   string `query:"id"`
	Body struct {
		GroupID *string `json:"groupId"`
	} `json:"body"`
}

func (e *PermissionsResource) UpdateMany(ctx context.Context, in *updatePermBulkInput) (*BulkResponse[PermissionDTO], error) {
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]PermissionDTO, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		p, _, err := e.svc.Get(ctx, domain.PermissionID(id))
		if err != nil {
			continue
		}
		var gid *domain.PermissionGroupID
		if in.Body.GroupID != nil {
			v := strings.TrimSpace(*in.Body.GroupID)
			if v != "" {
				tmp := domain.PermissionGroupID(v)
				gid = &tmp
			}
		}
		updated, outGID, uerr := e.svc.Update(ctx, domain.Permission{ID: p.ID, Name: p.Name, Code: p.Code}, gid)
		if uerr != nil {
			return nil, fmt.Errorf("permission bulk update id %s: %w", id, uerr)
		}
		var groupID *string
		if outGID != nil {
			v := string(*outGID)
			groupID = &v
		}
		out = append(out, PermissionDTO{
			ID:        string(updated.ID),
			Name:      updated.Name,
			Code:      updated.Code,
			GroupID:   groupID,
			CreatedAt: unixMilliToRFC3339(updated.CreatedAt),
		})
	}
	return &BulkResponse[PermissionDTO]{Body: BulkPayload[PermissionDTO]{Items: out}}, nil
}

func (e *PermissionsResource) DeleteMany(ctx context.Context, in *idsQuery) (*BulkResponse[PermissionDTO], error) {
	if err := enforce(ctx, e.engine, "permissions:write", "/permissions"); err != nil {
		return nil, err
	}
	ids := splitIDs(in.ID)
	out := make([]PermissionDTO, 0, len(ids))
	for _, id := range ids {
		item, err := e.Get(ctx, &userIDPath{ID: id})
		if err == nil && item != nil {
			out = append(out, item.Body)
		}
		if _, err := e.Delete(ctx, &userIDPath{ID: id}); err != nil {
			return nil, err
		}
	}
	return &BulkResponse[PermissionDTO]{Body: BulkPayload[PermissionDTO]{Items: out}}, nil
}
