package jwt

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"

	api "github.com/karantin2020/jwtis/api/jwt/v1"
	"github.com/karantin2020/jwtis/pkg/errdef"
	errors "github.com/pkg/errors"
)

type grpcServer struct {
	logger *zap.Logger
	svc    Service
	api.UnimplementedJWTServer
}

// NewJWTServer creates new JWTServer instance
func NewJWTServer(service Service, log *zap.Logger) api.JWTServer {
	return &grpcServer{
		logger: log.With(zap.String("component", "jwt_grpc_server")),
		svc:    service,
	}
}

// NewJWT protobuf implementation : no streaming for NewJWT
func (s *grpcServer) NewJWT(ctx context.Context, req *api.NewJWTRequest) (*api.NewJWTResponse, error) {
	// decReq := NewNewJWTRequestFromPB(req)
	if len(req.KID) < 3 {
		return nil, errors.Wrapf(errdef.ErrInvalidKID, "error in NewJWTRequest, invalid kid: '%s', length %d", req.KID, len(req.KID))
	}
	if req.Claims != nil && len(req.Claims) > 2 && len(req.Claims) < 5 {
		return nil, errors.Wrapf(errdef.ErrInvalidClaims, "error in NewJWTRequest, invalid claims: '%s', length %d", req.Claims, len(req.Claims))
	}
	claims := make(map[string]interface{})
	err := json.Unmarshal(req.Claims, &claims)
	if err != nil {
		return nil, errors.Wrap(errdef.ErrUnmarshalRequest, "error Unmarshal NewJWTRequest claims: "+err.Error())
	}
	decReq := &NewJWTRequest{
		KID:    req.KID,
		Claims: claims,
	}
	resp, err := s.svc.NewJWT(ctx, decReq)
	if err != nil {
		s.logger.Error("new jwt error", zap.String("operation", "newJWT"), zap.Error(err))
		return nil, err
	}
	return NewPBFromNewJWTResponse(resp), nil
}

// RenewJWT protobuf implementation : no streaming for RenewJWT
func (s *grpcServer) RenewJWT(ctx context.Context, req *api.RenewJWTRequest) (*api.RenewJWTResponse, error) {
	decReq := NewRenewJWTRequestFromPB(req)
	resp, err := s.svc.RenewJWT(ctx, decReq)
	if err != nil {
		s.logger.Error("renew jwt error", zap.String("operation", "renewJWT"), zap.Error(err))
		return nil, err
	}
	return NewPBFromRenewJWTResponse(resp), nil
}

// RevokeJWT protobuf implementation : no streaming for RevokeJWT
func (s *grpcServer) RevokeJWT(ctx context.Context, req *api.RevokeJWTRequest) (*api.RevokeJWTResponse, error) {
	decReq := NewRevokeJWTRequestFromPB(req)
	resp, err := s.svc.RevokeJWT(ctx, decReq)
	if err != nil {
		s.logger.Error("revoke jwt error", zap.String("operation", "revokeJWT"), zap.Error(err))
		return nil, err
	}
	return NewPBFromRevokeJWTResponse(resp), nil
}
