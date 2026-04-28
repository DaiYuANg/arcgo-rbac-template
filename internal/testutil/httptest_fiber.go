package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// setRequestBodyLength helps Fiber/fasthttp pass the full body into Huma when using httptest.
func setRequestBodyLength(req *http.Request, body io.Reader) {
	if body == nil {
		return
	}
	switch v := body.(type) {
	case *bytes.Reader:
		n := int64(v.Len())
		req.ContentLength = n
		req.Header.Set("Content-Length", strconv.FormatInt(n, 10))
	case *strings.Reader:
		n := int64(v.Len())
		req.ContentLength = n
		req.Header.Set("Content-Length", strconv.FormatInt(n, 10))
	case *bytes.Buffer:
		n := int64(v.Len())
		req.ContentLength = n
		req.Header.Set("Content-Length", strconv.FormatInt(n, 10))
	}
}

// FiberResponse is Fiber app.Test outcome with captured headers/body for cookie-based flows (e.g. refresh).
type FiberResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// FiberRequest runs a Fiber app request without JSON marshal (use FiberDoJSON when sending JSON structs).
func FiberRequest(tb testing.TB, app *fiber.App, method, path string, body io.Reader, header map[string]string) FiberResponse {
	tb.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, body)
	req.Header.Set("Content-Type", "application/json")
	setRequestBodyLength(req, body)
	for k, v := range header {
		if k != "" && v != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := app.Test(req, -1)
	if err != nil {
		tb.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			tb.Errorf("close response body: %v", closeErr)
		}
	}()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}

	return FiberResponse{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: got}
}

// FiberDoJSON executes a request against a Fiber app and returns status plus raw body bytes.
func FiberDoJSON(tb testing.TB, app *fiber.App, method, path string, payload any, header map[string]string) (int, []byte) {
	tb.Helper()
	res := FiberDoJSONDetailed(tb, app, method, path, payload, header)
	return res.StatusCode, res.Body
}

// FiberDoJSONDetailed is like FiberDoJSON but includes response headers for Set-Cookie etc.
func FiberDoJSONDetailed(tb testing.TB, app *fiber.App, method, path string, payload any, header map[string]string) FiberResponse {
	tb.Helper()
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			tb.Fatalf("marshal: %v", err)
		}
		body = bytes.NewReader(b)
	}

	return FiberRequest(tb, app, method, path, body, header)
}
