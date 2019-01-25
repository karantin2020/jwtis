package http

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karantin2020/jwtis"
	"github.com/karantin2020/jwtis/services/keyservice"
)

// KeyHandlersGroup struct holds key handlers
type KeyHandlersGroup struct {
	srvc *keyservice.KeyService
}

/**
 *
 * @api {POST} /register/:kid Register new client with kid
 * @apiName Register client
 * @apiGroup KeyHandlers
 * @apiVersion  0.0.1
 *
 * @apiParam  {String} kid Key id to register
 *
 * @apiSuccess (201) {Object} RegisterClientResponse Send client registration info
 *
 * @apiParamExample  {String} Request-Example:
 * {
 *     kid : testkid
 * }
 *
 *
 * @apiSuccessExample {type} Success-Response:
 * {
 *     RegisterClientResponse : RegisterClientResponse{}
 * }
 *
 *
 */

// Register handler
func (g *KeyHandlersGroup) Register(c *gin.Context) {
	var req RegisterClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("error parsing RegisterClientRequest from request body")
		c.JSON(http.StatusBadRequest, &ErrorResponse{
			Status: http.StatusBadRequest,
			Errors: []ErrorBody{
				{
					Source: "/",
					Title:  "invalid request data",
					Detail: "request body must be json and correspond to RegisterClientRequest{} structure",
				},
			},
		})
		return
	}

	// Must validate request data

	kid := c.Param("kid")
	var opts = &jwtis.DefaultOptions{
		SigAlg:          req.SigAlg,
		SigBits:         req.SigBits,
		EncAlg:          req.EncAlg,
		EncBits:         req.EncBits,
		Expiry:          time.Duration(req.Expiry),
		AuthTTL:         time.Duration(req.AuthTTL),
		RefreshTTL:      time.Duration(req.RefreshTTL),
		RefreshStrategy: req.RefreshStrategy,
	}
	pubKeys, err := g.srvc.Register(kid, opts)
	if err != nil {
		if err == jwtis.ErrKeysExist {
			log.Error().Err(err).Msgf("error registering new client with kid '%s'; client with that kid exists", kid)
			c.JSON(http.StatusForbidden, &ErrorResponse{
				Status: http.StatusForbidden,
				Errors: []ErrorBody{
					{
						Source: "/",
						Title:  "keys exist",
						Detail: err.Error(),
					},
				},
			})
			return
		}
		if err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysExistInvalid {
			log.Error().Err(err).Msgf("error registering new client with kid '%s'; client with that kid exists", kid)
			c.JSON(http.StatusConflict, &ErrorResponse{
				Status: http.StatusConflict,
				Errors: []ErrorBody{
					{
						Source: "/",
						Title:  "keys exist and are expired or invalid",
						Detail: err.Error(),
					},
				},
			})
			return
		}
		log.Error().Err(err).Msg("error registering new client, internal server error")
		c.JSON(http.StatusInternalServerError, &ErrorResponse{
			Status: http.StatusInternalServerError,
			Errors: []ErrorBody{
				{
					Source: "",
					Title:  "internal server error",
					Detail: "key service error, couldn't create new key; request key status: " + err.Error(),
				},
			},
		})
		return
	}
	log.Info().Msgf("registered new client with kid '%s', not expired and valid", kid)
	c.JSON(http.StatusCreated, &RegisterClientResponse{
		Kid:         kid,
		ClientToken: "",
		PubSigKey:   *pubKeys.Sig,
		PubEncKey:   *pubKeys.Enc,
		Expiry:      pubKeys.Expiry,
		Valid:       pubKeys.Valid,
	})
}

// GetPubKeys handler
func (g *KeyHandlersGroup) GetPubKeys(c *gin.Context) {
	kid := c.Param("kid")
	if kid == "" {
		c.JSON(http.StatusBadRequest, &ErrorResponse{
			Status: http.StatusBadRequest,
			Errors: []ErrorBody{
				{
					Source: "/",
					Title:  "invalid request",
					Detail: "kid is missing",
				},
			},
		})
		return
	}
	pubKeys, err := g.srvc.PublicKeys(kid)
	if err != nil {
		if err == jwtis.ErrKeysNotFound {
			log.Error().Err(err).Msg("error getting public keys, keys not found")
			c.JSON(http.StatusNotFound, &ErrorResponse{
				Status: http.StatusNotFound,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "keys not found",
						Detail: "error getting public keys: " + err.Error(),
					},
				},
			})
			return
		}
		if err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysInvalid {
			log.Error().Err(err).Msg("error getting public keys, keys are expired or invalid")
			c.JSON(http.StatusConflict, &ErrorResponse{
				Status: http.StatusConflict,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "keys are expired or invalid",
						Detail: "error getting public keys: " + err.Error(),
					},
				},
			})
			return
		}
		log.Error().Err(err).Msg("error getting public keys, internal server error")
		c.JSON(http.StatusInternalServerError, &ErrorResponse{
			Status: http.StatusInternalServerError,
			Errors: []ErrorBody{
				{
					Source: "",
					Title:  "internal server error",
					Detail: "error getting public keys: " + err.Error(),
				},
			},
		})
		return
	}
	log.Info().Msgf("sending public keys for kid '%s'", kid)
	c.JSON(http.StatusOK, &pubKeys)
}
