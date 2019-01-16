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
		c.JSON(http.StatusBadRequest, &ErrorRequest{
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
		SigAlg:     req.SigAlg,
		SigBits:    req.SigBits,
		EncAlg:     req.EncAlg,
		EncBits:    req.EncBits,
		Expiry:     time.Duration(req.Expiry),
		AuthTTL:    time.Duration(req.AuthTTL),
		RefreshTTL: time.Duration(req.RefreshTTL),
	}
	pubKeys, err := g.srvc.Register(kid, opts)
	if err != nil {
		if err == jwtis.ErrKeysExist || err == jwtis.ErrKeysExpired || err == jwtis.ErrKeysExistInvalid {
			log.Error().Err(err).Msgf("error registering new client with kid '%s'; client with that kid exists", kid)
			c.JSON(http.StatusForbidden, &ErrorRequest{
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
		log.Error().Err(err).Msg("error registering new client, internal server error")
		c.JSON(http.StatusInternalServerError, &ErrorRequest{
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
