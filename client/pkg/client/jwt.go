package client

import (
	"encoding/json"

	apiJWT "github.com/karantin2020/jwtis/api/jwt/v1"
	jwts "github.com/karantin2020/jwtis/pkg/services/jwt"
	"github.com/pkg/errors"
	// jose "gopkg.in/square/go-jose.v2"
	// jwt "gopkg.in/square/go-jose.v2/jwt"
)

func (c *clientImpl) NewJWT(in *jwts.NewJWTRequest) (*jwts.NewJWTResponse, error) {
	var claims []byte
	var err error
	if in.Claims == nil {
		claims = []byte("{}")
	} else {
		claims, err = json.Marshal(in.Claims)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal claims")
		}
	}
	pbReq := &apiJWT.NewJWTRequest{
		KID:    in.KID,
		Claims: claims,
	}
	resp, err := c.jwtClient.NewJWT(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "jwtClient: error call NewJWT")
	}
	return jwts.NewNewJWTResponseFromPB(resp), nil
}

func (c *clientImpl) RenewJWT(in *jwts.RenewJWTRequest) (*jwts.RenewJWTResponse, error) {
	pbReq := jwts.NewPBFromRenewJWTRequest(in)
	resp, err := c.jwtClient.RenewJWT(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "jwtClient: error call RenewJWT")
	}
	return jwts.NewRenewJWTResponseFromPB(resp), nil
}

func (c *clientImpl) RevokeJWT(in *jwts.RevokeJWTRequest) (*jwts.RevokeJWTResponse, error) {
	pbReq := jwts.NewPBFromRevokeJWTRequest(in)
	resp, err := c.jwtClient.RevokeJWT(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "jwtClient: error call RevokeJWT")
	}
	return jwts.NewRevokeJWTResponseFromPB(resp), nil
}
