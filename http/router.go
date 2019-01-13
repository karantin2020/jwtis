package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/karantin2020/jwtis/services/keyservice"
)

// LoadRouter loads new gin router with middleware
func LoadRouter(mode string, keySrvc *keyservice.KeyService, middleware ...gin.HandlerFunc) http.Handler {
	gin.SetMode(mode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(middleware...)
	khg := KeyHandlersGroup{keySrvc}
	r.GET("/", func(c *gin.Context) {
		// time.Sleep(10 * time.Second)
		c.String(http.StatusOK, "Welcome to Gin Server")
	})
	r.POST("/register/:kid", khg.Register)
	pingGroup(r.Group("/ping"))
	return r
}

func pingGroup(r *gin.RouterGroup) *gin.RouterGroup {
	r.GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome to ping route")
	})
	return r
}
