package httpapi

// Contract types aligned with `DaiYuANg/refine-rbac-template` backend spec.

type HealthResponse struct {
	Status string `json:"status"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken string `json:"accessToken"`
}

type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type MeResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email,omitempty"`
	Roles       []RoleRef `json:"roles"`
	Permissions []string  `json:"permissions"`
}

type PageResponse[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int64 `json:"page"`
	PageSize int64 `json:"pageSize"`
}

type UserDTO struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
	RoleIDs   []string `json:"roleIds,omitempty"`
	CreatedAt string   `json:"createdAt,omitempty"`
}

type RoleDTO struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Description        string   `json:"description,omitempty"`
	PermissionGroupIDs []string `json:"permissionGroupIds,omitempty"`
	CreatedAt          string   `json:"createdAt,omitempty"`
}

type PermissionDTO struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Code      string  `json:"code"`
	GroupID   *string `json:"groupId,omitempty"`
	CreatedAt string  `json:"createdAt,omitempty"`
}

type PermissionGroupDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
}

type BulkItems[T any] struct {
	Items []T `json:"items"`
}

type DashboardStatsResponse struct {
	StatCards []struct {
		Key      string `json:"key"`
		Value    int64  `json:"value"`
		LabelKey string `json:"labelKey"`
	} `json:"statCards"`

	UserActivity []struct {
		Month  string `json:"month"`
		Users  int64  `json:"users"`
		Logins int64  `json:"logins"`
	} `json:"userActivity"`

	RoleDistribution []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
		Color string `json:"color"`
	} `json:"roleDistribution"`

	PermissionGroups []struct {
		Name  string `json:"name"`
		Count int64  `json:"count"`
	} `json:"permissionGroups"`
}

