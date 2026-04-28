package httpapi

// userIDPath is shared across resources for `:id`-style routes.
type userIDPath struct {
	ID string `path:"id" validate:"required"`
}
