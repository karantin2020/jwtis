package transport

import (
	"context"

	kittransport "github.com/go-kit/kit/transport"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/metadata"

	uid "github.com/segmentio/ksuid"
)

// logErrorHandler is a transport error handler implementation which logs an error.
type logErrorHandler struct {
	logger zerolog.Logger
}

// NewLogErrorHandler func returns transport.ErrorHandler
func NewLogErrorHandler(logger zerolog.Logger) kittransport.ErrorHandler {
	return &logErrorHandler{
		logger: logger,
	}
}

// Handle func
func (h *logErrorHandler) Handle(ctx context.Context, err error) {
	h.logger.Err(err).Send()
}

// RequestIDKey to store
const RequestIDKey = "X-REQUEST-ID"

// Key to use when setting the request ID.
type ctxKeyRequestID int

// CtxRequestIDKey is the key that holds the unique request ID in a request context.
const CtxRequestIDKey ctxKeyRequestID = 0

// RequestID is a middleware that injects a request ID into the context of each
// request. A request ID is a string of the form "host.example.com/ksuid.KSUID"
func RequestID(name string) kitgrpc.ServerRequestFunc {
	return func(ctx context.Context, md metadata.MD) context.Context {
		id := md.Get(RequestIDKey)
		var rID string
		if len(id) > 0 && len(id[0]) > 0 {
			rID = id[0]
		} else {
			rID = uid.New().String()
		}
		ctx = context.WithValue(ctx, CtxRequestIDKey, rID)
		return ctx
	}
}

// GetReqID returns a request ID from the given context if one is present.
// Returns the empty string if a request ID cannot be found.
func GetReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if reqID, ok := ctx.Value(CtxRequestIDKey).(string); ok {
		return reqID
	}
	return ""
}
