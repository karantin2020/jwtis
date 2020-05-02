package client

import (
	"context"
	"encoding/json"
	"io"

	keysRepo "github.com/karantin2020/jwtis/pkg/repos/keys"
	keys "github.com/karantin2020/jwtis/pkg/services/keys"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func (c *clientImpl) Auth(ctx context.Context, in *keys.AuthRequest) (*keys.AuthResponse, error) {
	pbReq := keys.NewPBFromAuthRequest(in)
	resp, err := c.keysClient.Auth(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "keysClient: error call Auth")
	}
	return keys.NewAuthResponseFromPB(resp), nil
}

func (c *clientImpl) Register(ctx context.Context, in *keys.RegisterRequest) (*keys.RegisterResponse, error) {
	pbReq := keys.NewPBFromRegisterRequest(in)
	resp, err := c.keysClient.Register(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "keysClient: error call Register")
	}
	var result = keys.RegisterResponse{
		KID:     resp.KID,
		AuthJWT: resp.AuthJWT,
	}
	var sigKey jose.JSONWebKey
	err = json.Unmarshal(resp.PubSigKey, &sigKey)
	if err != nil {
		return nil, err
	}
	var encKey jose.JSONWebKey
	err = json.Unmarshal(resp.PubEncKey, &encKey)
	if err != nil {
		return nil, err
	}
	result.Keys = &keysRepo.SigEncKeys{
		Sig:             sigKey,
		Enc:             encKey,
		Expiry:          jwt.NumericDate(resp.Expiry),
		Valid:           resp.Valid,
		RefreshStrategy: resp.RefreshStrategy,
	}
	return &result, nil
}

func (c *clientImpl) UpdateKeys(ctx context.Context, in *keys.UpdateKeysRequest) (*keys.UpdateKeysResponse, error) {
	pbReq := keys.NewPBFromUpdateKeysRequest(in)
	resp, err := c.keysClient.UpdateKeys(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "keysClient: error call UpdateKeys")
	}
	var result = keys.UpdateKeysResponse{
		KID:     resp.KID,
		AuthJWT: resp.AuthJWT,
	}
	var sigKey jose.JSONWebKey
	err = json.Unmarshal(resp.PubSigKey, &sigKey)
	if err != nil {
		return nil, err
	}
	var encKey jose.JSONWebKey
	err = json.Unmarshal(resp.PubEncKey, &encKey)
	if err != nil {
		return nil, err
	}
	result.Keys = &keysRepo.SigEncKeys{
		Sig:             sigKey,
		Enc:             encKey,
		Expiry:          jwt.NumericDate(resp.Expiry),
		Valid:           resp.Valid,
		RefreshStrategy: resp.RefreshStrategy,
	}
	return &result, nil
}

func (c *clientImpl) ListKeys(ctx context.Context, in *keys.ListKeysRequest) ([]*keys.ListKeysResponse, error) {
	listKeys := []*keys.ListKeysResponse{}
	pbReq := keys.NewPBFromListKeysRequest(in)
	stream, err := c.keysClient.ListKeys(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "keysClient: error call ListKeys")
	}
	// receiving from server loop
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			// read done
			return listKeys, nil
		}
		if err != nil {
			return nil, err
		}

		sigKey, err := json.Marshal(message.PubSigKey)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal Sig key")
		}
		encKey, err := json.Marshal(message.PubEncKey)
		if err != nil {
			return nil, errors.Wrap(err, "error marshal Enc key")
		}
		var domResp = keys.ListKeysResponse{
			KID: message.KID,
			Keys: keysRepo.InfoSet{
				Expiry:          message.Expiry,
				AuthTTL:         message.AuthTTL,
				RefreshTTL:      message.RefreshTTL,
				RefreshStrategy: message.RefreshStrategy,
				Locked:          message.Locked,
				Valid:           message.Valid,
				Expired:         message.Expired,
				Enc:             encKey,
				Sig:             sigKey,
			},
		}
		listKeys = append(listKeys, &domResp)
	}
}

func (c *clientImpl) DelKeys(ctx context.Context, in *keys.DelKeysRequest) (*keys.DelKeysResponse, error) {
	pbReq := keys.NewPBFromDelKeysRequest(in)
	resp, err := c.keysClient.DelKeys(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "keysClient: error call DelKeys")
	}
	return keys.NewDelKeysResponseFromPB(resp), nil
}

func (c *clientImpl) PublicKeys(ctx context.Context, in *keys.PublicKeysRequest) (*keys.PublicKeysResponse, error) {
	pbReq := keys.NewPBFromPublicKeysRequest(in)
	resp, err := c.keysClient.PublicKeys(c.ctx, pbReq, c.callOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "keysClient: error call PublicKeys")
	}
	var sigKey jose.JSONWebKey
	err = json.Unmarshal(resp.PubSigKey, &sigKey)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshal sigKey")
	}
	var encKey jose.JSONWebKey
	err = json.Unmarshal(resp.PubEncKey, &encKey)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshal encKey")
	}
	var result = keys.PublicKeysResponse{
		KID: resp.KID,
		Keys: &keysRepo.SigEncKeys{
			Expiry: jwt.NumericDate(resp.Expiry),
			Valid:  resp.Valid,
			Sig:    sigKey,
			Enc:    encKey,
		},
	}
	return &result, nil
}
