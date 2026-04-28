package httpapi

import "github.com/gofiber/fiber/v2"

// FiberBinding describes a fiber middleware attachment to a route prefix.
// Each endpoint can contribute its own bindings through dix collection contributions.
type FiberBinding struct {
	Prefix  string
	Handler fiber.Handler
}

// FiberBinder is a small contract implemented by endpoints that need fiber middleware bindings.
// Each endpoint contributes itself into the dix collection role FiberBinder.
type FiberBinder interface {
	FiberBinding() FiberBinding
}
