package server

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/karantin2020/errorpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// UnaryPanicHandler handles panics for UnaryHandlers.
func UnaryPanicHandler() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = errorpb.New(codes.Internal, "panic recovered", fmt.Sprintf("%v", r))
				log.Error().Err(err).Str("stack", string(debug.Stack())).Msgf("recovered from panic: %v", r)
			}
		}()
		return handler(ctx, req)
	}

}
