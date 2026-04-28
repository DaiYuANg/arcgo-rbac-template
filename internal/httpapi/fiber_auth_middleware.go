package httpapi

import (
	"context"
	"strings"

	"github.com/arcgolabs/authx"
	authjwt "github.com/arcgolabs/authx/jwt"
	"github.com/gofiber/fiber/v2"
)

func requireAuthFiber(engine *authx.Engine) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		if ctx == nil {
			ctx = context.Background()
		}

		raw := strings.TrimSpace(c.Get("Authorization"))
		if !strings.HasPrefix(raw, "Bearer ") {
			return c.Status(401).JSON(fiber.Map{"message": "unauthorized"})
		}
		token := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"message": "unauthorized"})
		}

		result, err := engine.Check(ctx, authjwt.NewTokenCredential(token))
		if err != nil || result.Principal == nil {
			return c.Status(401).JSON(fiber.Map{"message": "unauthorized"})
		}

		c.SetUserContext(authx.WithPrincipal(ctx, result.Principal))
		return c.Next()
	}
}

func requirePermissionFiber(engine *authx.Engine, action, resource string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		if ctx == nil {
			ctx = context.Background()
		}

		raw := strings.TrimSpace(c.Get("Authorization"))
		if !strings.HasPrefix(raw, "Bearer ") {
			return c.Status(401).JSON(fiber.Map{"message": "unauthorized"})
		}
		token := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"message": "unauthorized"})
		}

		result, err := engine.Check(ctx, authjwt.NewTokenCredential(token))
		if err != nil || result.Principal == nil {
			return c.Status(401).JSON(fiber.Map{"message": "unauthorized"})
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

