package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karantin2020/jwtis/services/jwtservice"
	"github.com/karantin2020/jwtis/services/keyservice"
)

// LoadRouter loads new gin router with middleware
func LoadRouter(mode string, keySrvc *keyservice.KeyService,
	jwtSrvc *jwtservice.JWTService,
	middleware ...gin.HandlerFunc) http.Handler {

	khg := &KeyHandlersGroup{keySrvc}
	jhg := &JWTHandlersGroup{jwtSrvc}

	gin.SetMode(mode)
	r := gin.New()
	r.RedirectFixedPath = true
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(middleware...)
	r.GET("/", func(c *gin.Context) {
		// time.Sleep(10 * time.Second)
		c.String(http.StatusOK, "Welcome to Gin Server")
	})
	r.POST("/register/:kid", khg.Register)
	r.GET("/keys/:kid", khg.GetPubKeys)
	r.POST("/issue_token", jhg.NewToken)
	r.POST("/renew_token", jhg.RenewToken)
	pingGroup(r.Group("/ping"))
	return r
}

func pingGroup(r *gin.RouterGroup) *gin.RouterGroup {
	r.GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome to ping route")
	})
	return r
}
