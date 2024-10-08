package auth

import (
	"fresh-grad-jobs/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LoginHandler handles the user login and generates a token
func SignInHandler(c *gin.Context) {
	// Declare a struct to bind the JSON request
	var loginRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	// Bind the JSON body to the struct
	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format"})
		return
	}

	db, err := services.ConnectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer db.Close() // Ensure the database connection is closed

	token, err := services.GenerateJWT(loginRequest.Email, loginRequest.Password, db)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": err.Error()})
		return
	}

	// Return the generated token
	c.JSON(http.StatusOK, gin.H{"token": token})
}
