package service

import (
	"context"

	"github.com/karantin2020/jwtis"
	"github.com/rs/zerolog"
)

// JWTMiddleware describes a service (as opposed to endpoint) middleware.
type JWTMiddleware func(JWTService) JWTService

// JWTLoggingMiddleware takes a logger as a dependency
// and returns a service Middleware.
func JWTLoggingMiddleware(zlog zerolog.Logger) JWTMiddleware {
	return func(next JWTService) JWTService {
		return jwtLoggingMiddleware{
			logger: zlog,
			next:   next,
		}
	}
}

type jwtLoggingMiddleware struct {
	logger zerolog.Logger
	next   JWTService
}

func (mw jwtLoggingMiddleware) NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (pair *JWTPair, err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "NewJWT").Str("log_id", logID).
		Str("at", "start").Str("kid", kid).Interface("claims", claims).Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "NewJWT").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.NewJWT(ctx, kid, claims)
}

func (mw jwtLoggingMiddleware) RenewJWT(ctx context.Context, kid, refresh, refreshStrategy string) (pair *JWTPair, err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "RenewJWT").Str("log_id", logID).
		Str("at", "start").Str("kid", kid).Str("refresh", refresh).
		Str("refreshStrategy", refreshStrategy).Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "RenewJWT").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.RenewJWT(ctx, kid, refresh, refreshStrategy)
}

// ====================== //

// KeysMiddleware describes a service (as opposed to endpoint) middleware.
type KeysMiddleware func(KeysService) KeysService

// KeysLoggingMiddleware takes a logger as a dependency
// and returns a service Middleware.
func KeysLoggingMiddleware(zlog zerolog.Logger) KeysMiddleware {
	return func(next KeysService) KeysService {
		return keysLoggingMiddleware{
			logger: zlog,
			next:   next,
		}
	}
}

type keysLoggingMiddleware struct {
	logger zerolog.Logger
	next   KeysService
}

func (mw keysLoggingMiddleware) Register(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (rep *jwtis.SigEncKeys, err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "Register").Str("log_id", logID).
		Str("at", "start").Str("kid", kid).Interface("opts", opts).Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "Register").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.Register(ctx, kid, opts)
}
func (mw keysLoggingMiddleware) UpdateKeys(ctx context.Context, kid string, opts *jwtis.DefaultOptions) (rep *jwtis.SigEncKeys, err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "UpdateKeys").Str("log_id", logID).
		Str("at", "start").Str("kid", kid).Interface("opts", opts).Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "UpdateKeys").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.UpdateKeys(ctx, kid, opts)
}
func (mw keysLoggingMiddleware) ListKeys(ctx context.Context) (rep []jwtis.KeysInfoSet, err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "ListKeys").Str("log_id", logID).
		Str("at", "start").Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "ListKeys").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.ListKeys(ctx)
}
func (mw keysLoggingMiddleware) DelKeys(ctx context.Context, kid string) (err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "DelKeys").Str("log_id", logID).
		Str("at", "start").Str("kid", kid).Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "DelKeys").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.DelKeys(ctx, kid)
}
func (mw keysLoggingMiddleware) PublicKeys(ctx context.Context, kid string) (rep *jwtis.SigEncKeys, err error) {
	logID := GetReqID(ctx)
	mw.logger.Info().Str("method", "PublicKeys").Str("log_id", logID).
		Str("at", "start").Str("kid", kid).Msg("")
	defer func() {
		mw.logger.Err(err).Str("method", "PublicKeys").Str("log_id", logID).
			Str("at", "finish").Msg("")
	}()
	return mw.next.PublicKeys(ctx, kid)
}

// ======================== //

// Key to use when setting the request ID
type ctxKeyRequestID int

// CtxRequestIDKey is the key that holds the unique request ID in a request context
const CtxRequestIDKey ctxKeyRequestID = 0

// GetReqID returns a request ID from the given context if one is present
// Returns the empty string if a request ID cannot be found
func GetReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if reqID, ok := ctx.Value(CtxRequestIDKey).(string); ok {
		return reqID
	}
	return ""
}
