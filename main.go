package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func keyFunc(c *gin.Context) string {
	return c.ClientIP()
}

func errorHandler(c *gin.Context, info Info) {
	c.String(429, "Too many requests. Try again in "+time.Until(info.ResetTime).String())
}

func main() {
	LoadSettings()
	InitDB()

	// check db
	if !CheckDBOnline() {
		log.Fatal("Database is offline")
		return
	}

	store := InMemoryStore(&InMemoryOptions{
		Rate:  time.Second,
		Limit: 6,
	})

	mw := RateLimiter(store, &Options{
		ErrorHandler: errorHandler,
		KeyFunc:      keyFunc,
	})

	gin.SetMode(gin.ReleaseMode)
	e := gin.Default()
	e.Use(gin.Recovery())

	e.POST("/v1", mw, HandleRequest)

	e.POST("/v3", mw, HandleUniversalRequest)
	e.POST("/subscription", mw, HandleSub)
	e.GET("/status", mw, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "up",
		})
	})

	e.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusForbidden, gin.H{
			"status": "forbidden",
		})
	})

	e.Run(":4444")

}
