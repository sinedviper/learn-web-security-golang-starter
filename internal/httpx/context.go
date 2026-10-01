package httpx

import (
	"context"
	"uuid"
)

type contextKey string

const cspNonceContextKey contextKey = "csp-nonce"
const requestIDContextKey contextKey = "request-id"

func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKey, nonce)
}

func CSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceContextKey).(string)
	return nonce
}

func WithRequestID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, requestIDContextKey, id)
}

func RequestID(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(requestIDContextKey).(uuid.UUID)
	return id
}
