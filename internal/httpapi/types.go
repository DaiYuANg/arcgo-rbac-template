package httpapi

// Contract types aligned with `DaiYuANg/refine-rbac-template` backend spec.

type HealthResponse struct {
	// Not named "Status": Huma reserves that field for HTTP status code (int) on response types.
	State string `json:"status"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type TokenResponse struct {
	AccessToken string `json:"accessToken"`
}

type AuthAuditLogDTO struct {
	Event            string `json:"event"`
	UserID           string `json:"userId"`
	Username         string `json:"username"`
	ClientIP         string `json:"clientIp"`
	Success          bool   `json:"success"`
	Reason           string `json:"reason"`
	CreatedAt        int64  `json:"createdAt"`
	CreatedAtRFC3339 string `json:"createdAtRFC3339"`
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

// PagePayload is the JSON shape for list endpoints (wrapped as PageResponse.Body for Huma v2).
type PagePayload[T any] struct {
	Items    []T   `json:"items"`
	Total    int64 `json:"total"`
	Page     int64 `json:"page"`
	PageSize int64 `json:"pageSize"`
}

// PageResponse wraps list payloads so Huma serializes Body as JSON with status 200.
type PageResponse[T any] struct {
	Body PagePayload[T] `doc:"Paged result"`
}

type UserDTO struct {
	ID        string   `json:"id"                  validate:"required"`
	Email     string   `json:"email"               validate:"required,email"`
	Name      string   `json:"name"                validate:"required"`
	RoleIDs   []string `json:"roleIds,omitempty"`
	CreatedAt string   `json:"createdAt,omitempty"`
}

type RoleDTO struct {
	ID                 string   `json:"id"                           validate:"required"`
	Name               string   `json:"name"                         validate:"required"`
	Description        string   `json:"description,omitempty"`
	PermissionGroupIDs []string `json:"permissionGroupIds,omitempty"`
	CreatedAt          string   `json:"createdAt,omitempty"`
}

type PermissionDTO struct {
	ID        string  `json:"id"                  validate:"required"`
	Name      string  `json:"name"                validate:"required"`
	Code      string  `json:"code"                validate:"required"`
	GroupID   *string `json:"groupId,omitempty"`
	CreatedAt string  `json:"createdAt,omitempty"`
}

type PermissionGroupDTO struct {
	ID          string `json:"id"                    validate:"required"`
	Name        string `json:"name"                  validate:"required"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
}

type BulkItems[T any] struct {
	Items []T `json:"items"`
}

type BulkPayload[T any] struct {
	Items []T `json:"items"`
}

// BulkResponse wraps bulk results for Huma v2 handlers (Body is what gets serialized as JSON).
type BulkResponse[T any] struct {
	Body BulkPayload[T] `doc:"Bulk items"`
}

// JSONBody wraps a payload for Huma v2: only Body is written as the response JSON (flat shape of T on the wire).
type JSONBody[T any] struct {
	Body T `doc:"Response payload"`
}

func wrapJSON[T any](v *T) *JSONBody[T] {
	if v == nil {
		return nil
	}
	return &JSONBody[T]{Body: *v}
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
