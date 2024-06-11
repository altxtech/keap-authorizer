package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func helloWorld(c *gin.Context){
	c.String(http.StatusOK, "Test deploy to dev")
}

func main() {
	
	app := gin.Default()
	app.GET("/", helloWorld)


	app.Run()
}
