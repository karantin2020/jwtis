package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// LoadRouter loads new gin router with middleware
func LoadRouter(mode string, middleware ...gin.HandlerFunc) http.Handler {
	gin.SetMode(mode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.Use(middleware...)
	r.GET("/", func(c *gin.Context) {
		// time.Sleep(10 * time.Second)
		c.String(http.StatusOK, "Welcome to Gin Server")
	})
	pingGroup(r.Group("/ping"))
	return r
}

func pingGroup(r *gin.RouterGroup) *gin.RouterGroup {
	r.GET("", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome to ping route")
	})
	return r
}
