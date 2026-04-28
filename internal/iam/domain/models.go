package domain

type User struct {
	ID        UserID
	Email     string
	Name      string
	CreatedAt int64
}

type Role struct {
	ID          RoleID
	Name        string
	Description string
	CreatedAt   int64
}

type Permission struct {
	ID        PermissionID
	Name      string
	Code      string
	CreatedAt int64
}

type PermissionGroup struct {
	ID          PermissionGroupID
	Name        string
	Description string
	CreatedAt   int64
}
