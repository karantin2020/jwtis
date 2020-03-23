package service

import (
	"context"

	log "github.com/go-kit/kit/log"
	"github.com/karantin2020/jwtis"
)

// Middleware describes a service middleware.
type Middleware func(JWTISService) JWTISService

type loggingMiddleware struct {
	logger log.Logger
	next   JWTISService
}

// LoggingMiddleware takes a logger as a dependency
// and returns a JWTISService Middleware.
func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next JWTISService) JWTISService {
		return &loggingMiddleware{logger, next}
	}

}

func (l loggingMiddleware) NewJWT(ctx context.Context, kid string, claims map[string]interface{}) (pair *JWTPair, err error) {
	defer func() {
		l.logger.Log("method", "NewJWT", "kid", kid, "claims", claims, "pair", pair, "err", err)
	}()
	return l.next.NewJWT(ctx, kid, claims)
}
func (l loggingMiddleware) RenewJWT(ctx context.Context, kid string, refreshToken string, refreshStrategy string) (pair *JWTPair, err error) {
	defer func() {
		l.logger.Log("method", "RenewJWT", "kid", kid, "refreshToken", refreshToken, "refreshStrategy", refreshStrategy, "pair", pair, "err", err)
	}()
	return l.next.RenewJWT(ctx, kid, refreshToken, refreshStrategy)
}
func (l loggingMiddleware) RevokeJWT(ctx context.Context, kid string, jwtID string, refreshToken string) (err error) {
	defer func() {
		l.logger.Log("method", "RevokeJWT", "kid", kid, "jwtID", jwtID, "refreshToken", refreshToken, "err", err)
	}()
	return l.next.RevokeJWT(ctx, kid, jwtID, refreshToken)
}
func (l loggingMiddleware) Auth(ctx context.Context, kid string) (token string, err error) {
	defer func() {
		l.logger.Log("method", "Auth", "kid", kid, "token", token, "err", err)
	}()
	return l.next.Auth(ctx, kid)
}
func (l loggingMiddleware) Register(ctx context.Context, kid string, opts *KeysOptions) (keys *jwtis.SigEncKeys, err error) {
	defer func() {
		l.logger.Log("method", "Register", "kid", kid, "opts", opts, "keys", keys, "err", err)
	}()
	return l.next.Register(ctx, kid, opts)
}
func (l loggingMiddleware) UpdateKeys(ctx context.Context, kid string, opts *KeysOptions) (keys *jwtis.SigEncKeys, err error) {
	defer func() {
		l.logger.Log("method", "UpdateKeys", "kid", kid, "opts", opts, "keys", keys, "err", err)
	}()
	return l.next.UpdateKeys(ctx, kid, opts)
}
func (l loggingMiddleware) ListKeys(ctx context.Context) (keysList []jwtis.KeysInfoSet, err error) {
	defer func() {
		l.logger.Log("method", "ListKeys", "keysList", keysList, "err", err)
	}()
	return l.next.ListKeys(ctx)
}
func (l loggingMiddleware) DelKeys(ctx context.Context, kid string) (err error) {
	defer func() {
		l.logger.Log("method", "DelKeys", "kid", kid, "err", err)
	}()
	return l.next.DelKeys(ctx, kid)
}
func (l loggingMiddleware) PublicKeys(ctx context.Context, kid string) (keys *jwtis.SigEncKeys, err error) {
	defer func() {
		l.logger.Log("method", "PublicKeys", "kid", kid, "keys", keys, "err", err)
	}()
	return l.next.PublicKeys(ctx, kid)
}
