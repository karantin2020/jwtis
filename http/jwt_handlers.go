package http

import (
	"net/http"

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

	// Add support for encrypted claims

	var req = NewTokenRequest{Claims: make(map[string]interface{})}
	if err := c.ShouldBindJSON(&req); err != nil || req.Kid == "" {
		c.JSON(http.StatusBadRequest, &ErrorResponse{
			Status: http.StatusBadRequest,
			Errors: []ErrorBody{
				{
					Source: "/",
					Title:  "invalid request data",
					Detail: "request body must be valid json and correspond to NewTokenRequest{} structure, atleast kid must be provided",
				},
			},
		})
		return
	}

	// Must validate request data

	tokens, err := g.srvc.NewJWT(req.Kid, req.Claims)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			log.Error().Err(err).Msgf("error creating new JWT for kid '%s': keys not exist", req.Kid)
			c.JSON(http.StatusNotFound, &ErrorResponse{
				Status: http.StatusNotFound,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "keys not found",
						Detail: "jwt service error, couldn't create new tokens, not found keys; err: " + err.Error(),
					},
				},
			})
			return
		}
		log.Error().Err(err).Msgf("error creating new JWT for kid '%s'", req.Kid)
		c.JSON(http.StatusInternalServerError, &ErrorResponse{
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
		c.JSON(http.StatusBadRequest, &ErrorResponse{
			Status: http.StatusBadRequest,
			Errors: []ErrorBody{
				{
					Source: "/",
					Title:  "invalid request data",
					Detail: "request body must be valid json and correspond to RenewTokenRequest{} structure, atleast kid must be provided",
				},
			},
		})
		return
	}

	// Must validate request data

	tokens, err := g.srvc.RenewJWT(req.Kid, req.RefreshToken)
	if err != nil {
		if err == jwtservice.ErrKIDNotExists {
			log.Error().Err(err).Msgf("error renew JWT for kid '%s': keys not exist", req.Kid)
			c.JSON(http.StatusNotFound, &ErrorResponse{
				Status: http.StatusNotFound,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "keys not found",
						Detail: "jwt service error, couldn't renew tokens, not found keys; err: " + err.Error(),
					},
				},
			})
			return
		}
		if err == jwtservice.ErrDecryptRefreshToken {
			log.Error().Err(err).Msgf("error renew JWT for kid '%s': invalid crypto primitives", req.Kid)
			c.JSON(http.StatusForbidden, &ErrorResponse{
				Status: http.StatusForbidden,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "invalid crypto primitives",
						Detail: "jwt service error, couldn't renew tokens, invalid cryptographic primitives; err: " + err.Error(),
					},
				},
			})
			return
		}
		if err == jwtservice.ErrRefreshTokenExpired {
			log.Error().Err(err).Msgf("error renew JWT for kid '%s': refresh token expired", req.Kid)
			c.JSON(http.StatusConflict, &ErrorResponse{
				Status: http.StatusConflict,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "refresh token expired",
						Detail: "jwt service error, couldn't renew tokens, refresh token expired; err: " + err.Error(),
					},
				},
			})
			return
		}
		if err == jwtservice.ErrInvalidRefreshClaims {
			log.Error().Err(err).Msgf("error renew JWT for kid '%s': invalid refresh claims", req.Kid)
			c.JSON(http.StatusUnprocessableEntity, &ErrorResponse{
				Status: http.StatusUnprocessableEntity,
				Errors: []ErrorBody{
					{
						Source: "",
						Title:  "invalid refresh claims",
						Detail: "jwt service error, couldn't renew tokens, invalid refresh claims; err: " + err.Error(),
					},
				},
			})
			return
		}
		log.Error().Err(err).Msgf("error renewing JWT for kid '%s'", req.Kid)
		c.JSON(http.StatusInternalServerError, &ErrorResponse{
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
