package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/gofiber/fiber/v2"
)

var errUnauthorized = errors.New("unauthorized")

func unauthorizedJSON(c *fiber.Ctx) error {
	if err := c.Status(401).JSON(fiber.Map{"message": "unauthorized"}); err != nil {
		return fmt.Errorf("write unauthorized response: %w", err)
	}
	return nil
}

func parseBearerToken(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "Bearer ") {
		return "", errUnauthorized
	}
	token := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if token == "" {
		return "", errUnauthorized
	}
	return token, nil
}

func authContext(c *fiber.Ctx) context.Context {
	ctx := c.UserContext()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func requireAuthFiber(engine *authx.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if engine == nil {
			return c.Status(500).JSON(fiber.Map{"message": "auth_engine_missing"})
		}
		ctx := authContext(c)
		token, err := parseBearerToken(c.Get("Authorization"))
		if err != nil {
			return unauthorizedJSON(c)
		}

		result, err := engine.Check(ctx, authjwt.NewTokenCredential(token))
		if err != nil || result.Principal == nil {
			return unauthorizedJSON(c)
		}

		c.SetUserContext(authx.WithPrincipal(ctx, result.Principal))
		return c.Next()
	}
}

func requirePermissionFiber(engine *authx.Engine, action, resource string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if engine == nil {
			return c.Status(500).JSON(fiber.Map{"message": "auth_engine_missing"})
		}
		ctx := authContext(c)
		token, err := parseBearerToken(c.Get("Authorization"))
		if err != nil {
			return unauthorizedJSON(c)
		}

		result, err := engine.Check(ctx, authjwt.NewTokenCredential(token))
		if err != nil || result.Principal == nil {
			return unauthorizedJSON(c)
		}

		decision, err := engine.Can(ctx, authx.AuthorizationModel{
			Principal: result.Principal,
			Action:    action,
			Resource:  resource,
		})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"message": "unknown"})
		}
		if !decision.Allowed {
			return c.Status(403).JSON(fiber.Map{"message": "forbidden"})
		}

		c.SetUserContext(authx.WithPrincipal(ctx, result.Principal))
		return c.Next()
	}
}
