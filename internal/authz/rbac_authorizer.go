// Package authz implements authx authorization integration for the template.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/application"
	"github.com/arcgolabs/arcgo-rbac-template/internal/iam/domain"
	"github.com/arcgolabs/authx"
)

type IAMAuthorizer struct {
	iam *application.Authorizer
}

func NewIAMAuthorizer(iam *application.Authorizer) *IAMAuthorizer {
	return &IAMAuthorizer{iam: iam}
}

func (a *IAMAuthorizer) Authorize(ctx context.Context, input authx.AuthorizationModel) (authx.Decision, error) {
	p, ok := input.Principal.(authx.Principal)
	if !ok {
		// authx/jwt maps to authx.Principal, so this means the caller used a different provider.
		return authx.Decision{Allowed: false, Reason: "invalid principal"}, errors.New("principal type not supported")
	}

	uid := strings.TrimSpace(p.ID)
	if uid == "" {
		return authx.Decision{Allowed: false, Reason: "unauthenticated"}, authx.ErrUnauthenticated
	}

	perm := strings.TrimSpace(input.Action)
	if perm == "" {
		return authx.Decision{Allowed: false, Reason: "missing action"}, errors.New("missing action")
	}

	if a.iam == nil {
		return authx.Decision{Allowed: false, Reason: "iam not configured"}, errors.New("iam authorizer is nil")
	}

	decision, err := a.iam.Can(ctx, domain.UserID(uid), p.Roles.Values(), domain.PermissionID(perm), input.Resource)
	if err != nil {
		return authx.Decision{Allowed: false, Reason: "iam error"}, fmt.Errorf("iam authorize: %w", err)
	}

	return authx.Decision{
		Allowed:  decision.Allowed,
		Reason:   decision.Reason,
		PolicyID: "",
	}, nil
}

