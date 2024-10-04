package main

import (
	admin "fresh-grad-jobs/handlers/users" // Import your user handlers
	services "fresh-grad-jobs/services"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin" // Import Gin framework
)

// AdminAuthMiddleware checks for admin role in the JWT
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Authorization header missing or malformed"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token and get the user role
		role, err := services.ValidateJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "error": "Invalid Token"})
			c.Abort()
			return
		}

		// Check if the user role is "admin"
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func main() {
	// Create a new Gin router
	router := gin.Default()

	// login for Generate token
	router.POST("/login", func(c *gin.Context) {
		// Declare a struct to bind the JSON request
		var loginRequest struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}

		// Bind JSON body to the struct
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

		// Generate the JWT using the email and password from the request
		token, err := services.GenerateJWT(loginRequest.Email, loginRequest.Password, db)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": err.Error()})
			return
		}

		// Return the token
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	adminRoute := router.Group("/admin", AdminAuthMiddleware())
	{
		// Route for approving a user by ID
		adminRoute.POST("/users/approve/:user-id", admin.UserApprove)
		// Route for deleting a user by ID
		adminRoute.DELETE("/users/delete/:user-id", admin.UserDelete)
		// Route for retrieving users based on role
		// Get all users of a specific role
		adminRoute.GET("/users/views/:role", admin.UserViews)
		// Get a specific user by role and ID
		adminRoute.GET("/users/views/:role/:user-id", admin.UserViews)

		// Route for approving a job by ID
		adminRoute.GET("/jobs/approve/:job-id", admin.JobsApprove)
		// Route for deleting a job by ID
		adminRoute.GET("/jobs/delete/:job-id", admin.JobsDelete)
		// Route for retrieving jobs
		// Get all jobs with filters and pagination
		adminRoute.GET("/jobs/views", admin.JobsViews) // Updated path
		// Get a specific job by ID
		adminRoute.GET("/jobs/views/:job-id", admin.JobsViews)
	}

	// Run the server on port 8080
	router.Run(":8080")
}
