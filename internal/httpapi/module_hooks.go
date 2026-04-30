package httpapi

import (
	collectionlist "github.com/arcgolabs/collectionx/list"
	"github.com/arcgolabs/httpx"
	"github.com/gofiber/fiber/v2"
)

func registerFiberBinding(app *fiber.App, binder FiberBinder) {
	if binder == nil {
		return
	}
	b := binder.FiberBinding()
	if b.Prefix == "" || b.Handler == nil {
		return
	}
	app.Use(b.Prefix, b.Handler)
}

// RegisterFiberBindings registers authz-related Fiber middleware (same behavior as DI wire step).
func RegisterFiberBindings(app *fiber.App, binders ...FiberBinder) {
	for i := range binders {
		registerFiberBinding(app, binders[i])
	}
}

func wireFiberBinders(app *fiber.App, binders *collectionlist.List[FiberBinder]) {
	if binders == nil {
		return
	}
	binders.Range(func(_ int, binder FiberBinder) bool {
		registerFiberBinding(app, binder)
		return true
	})
}

func wireHTTPEndpoints(server httpx.ServerRuntime, endpoints *collectionlist.List[httpx.Endpoint]) {
	if endpoints == nil {
		return
	}
	endpoints.Range(func(_ int, ep httpx.Endpoint) bool {
		if ep != nil {
			server.Register(ep)
		}
		return true
	})
}
