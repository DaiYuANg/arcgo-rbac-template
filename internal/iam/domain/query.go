package domain

import (
	"strings"
)

type SortOrder string

const (
	SortAsc  SortOrder = "asc"
	SortDesc SortOrder = "desc"
)

func NormalizeOrder(v string) SortOrder {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == string(SortDesc) {
		return SortDesc
	}
	return SortAsc
}

type PageParams struct {
	Page     int64
	PageSize int64
}

type Page[T any] struct {
	Items    []T
	Total    int64
	Page     int64
	PageSize int64
}

type UsersListQuery struct {
	PageParams
	Q         string
	Sort      string
	Order     SortOrder
	NameLike  string
	EmailLike string
}

type RolesListQuery struct {
	PageParams
	Q        string
	Sort     string
	Order    SortOrder
	NameLike string
}

type PermissionsListQuery struct {
	PageParams
	Q        string
	Sort     string
	Order    SortOrder
	NameLike string
	CodeLike string
}

type PermissionGroupsListQuery struct {
	PageParams
	Q        string
	Sort     string
	Order    SortOrder
	NameLike string
}

