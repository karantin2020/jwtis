package http

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karantin2020/jwtis/services/jwtservice"
)

// JWTHandlersGroup struct holds JWT handlers
type JWTHandlersGroup struct {
	srvc *jwtservice.JWTService
}

/**
 *
 * @api {POST} /issue_token Issue new JWT token for certain kid
 * @apiName Issue new token
 * @apiGroup JWTHandlers
 * @apiVersion  0.0.1
 *
 * @apiParam  {Object} NewTokenRequest Info to issue new token
 *
 * @apiSuccess (201) {Object} NewTokenResponse Send new JWT tokens
 *
 * @apiParamExample  {Object} Request-Example:
 * {
 *     kid : testkid
 * }
 *
 *
 * @apiSuccessExample {Object} Success-Response:
 * {
 *     NewTokenResponse : NewTokenResponse{}
 * }
 *
 *
 */

// NewToken handler
func (g *JWTHandlersGroup) NewToken(c *gin.Context) {
	var req = NewTokenRequest{Claims: make(map[string]interface{})}
	if err := c.ShouldBindJSON(&req); err != nil || req.Kid == "" {
		c.JSON(http.StatusBadRequest, &ErrorRequest{
			Status: http.StatusBadRequest,
			Errors: []ErrorBody{
				{
					Source: "/",
					Title:  "invalid request data",
					Detail: "request body must be json and correspond to NewTokenRequest{} structure, atleast kid must be provided",
				},
			},
		})
		return
	}

	// Must validate request data

	tokens, err := g.srvc.NewJWT(req.Kid, req.Claims,
		time.Duration(req.AccessTokenValidTime),
		time.Duration(req.ResreshTokenValidTime))
	if err != nil {
		log.Error().Err(err).Msgf("error creating new JWT for kid '%s'", req.Kid)
		c.JSON(http.StatusInternalServerError, &ErrorRequest{
			Status: http.StatusInternalServerError,
			Errors: []ErrorBody{
				{
					Source: "",
					Title:  "internal server error",
					Detail: "jwt service error, couldn't create new tokens; err: " + err.Error(),
				},
			},
		})
		return
	}
	log.Info().Msgf("new JWT for kid '%s' with id '%s' was created", req.Kid, tokens.ID)
	c.JSON(http.StatusCreated, &TokenResponse{
		ID:           tokens.ID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       tokens.Expiry,
	})
}

// RenewToken handler
func (g *JWTHandlersGroup) RenewToken(c *gin.Context) {
	var req = RenewTokenRequest{}
	if err := c.ShouldBindJSON(&req); err != nil || req.Kid == "" || req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, &ErrorRequest{
			Status: http.StatusBadRequest,
			Errors: []ErrorBody{
				{
					Source: "/",
					Title:  "invalid request data",
					Detail: "request body must be json and correspond to RenewTokenRequest{} structure, atleast kid must be provided",
				},
			},
		})
		return
	}

	// Must validate request data

	tokens, err := g.srvc.RenewJWT(req.Kid, req.RefreshToken,
		time.Duration(req.AccessTokenValidTime),
		time.Duration(req.ResreshTokenValidTime))
	if err != nil {
		log.Error().Err(err).Msgf("error renewing JWT for kid '%s'", req.Kid)
		c.JSON(http.StatusInternalServerError, &ErrorRequest{
			Status: http.StatusInternalServerError,
			Errors: []ErrorBody{
				{
					Source: "",
					Title:  "internal server error",
					Detail: "jwt service error, couldn't renew tokens; err: " + err.Error(),
				},
			},
		})
		return
	}
	log.Info().Msgf("JWT for kid '%s' with id '%s' was renewed", req.Kid, tokens.ID)
	c.JSON(http.StatusCreated, &TokenResponse{
		ID:           tokens.ID,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Expiry:       tokens.Expiry,
	})
}
