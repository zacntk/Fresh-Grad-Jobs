package main

import (
	"fmt"
	adminController "fresh-grad-jobs/handlers/users" // Import your user handlers
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin" // Import Gin framework
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("freshgradjobsismypraticeofgo")

func GenerateJWT() (string, error) {
	claims := jwt.MapClaims{
		"role": "admin",
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iss":  "freshgradjobs",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func validateAdminJWT(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid && claims["role"] == "admin" {
		return nil
	} else {
		return fmt.Errorf("invalid token")
	}
}

func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Authorization header missing or malformed"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		if err := validateAdminJWT(token); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "error": "Invalid Token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func main() {
	// Create a new Gin router
	router := gin.Default()

	// Generate Token JWT for admin
	router.GET("/", func(c *gin.Context) {
		token, _ := GenerateJWT()
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	adminControllUser := router.Group("/admin", AdminAuthMiddleware())
	{
		// Route for approving a user by ID
		adminControllUser.POST("/users/approve/:user-id", adminController.UserApprove)
		// Route for deleting a user by ID
		adminControllUser.DELETE("/users/delete/:user-id", adminController.UserDelete)
		// Route for retrieving users based on role
		// Get all users of a specific role
		adminControllUser.GET("/users/views/:role", adminController.UserViews)
		// Get a specific user by role and ID
		adminControllUser.GET("/users/views/:role/:user-id", adminController.UserViews)

		// Route for approving a job by ID
		adminControllUser.GET("/jobs/approve/:job-id", adminController.JobsApprove)
		// Route for deleting a job by ID
		adminControllUser.GET("/jobs/delete/:job-id", adminController.JobsDelete)
		// Route for retrieving jobs
		// Get all jobs with filters and pagination
		adminControllUser.GET("/jobs/views", adminController.JobsViews) // Updated path
		// Get a specific job by ID
		adminControllUser.GET("/jobs/views/:job-id", adminController.JobsViews)
	}

	// Run the server on port 8080
	router.Run(":8080")
}
