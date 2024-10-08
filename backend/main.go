package main

import (
	admin "fresh-grad-jobs/handlers/users/admin-controller"
	auth "fresh-grad-jobs/handlers/users/auth"
	"fresh-grad-jobs/handlers/users/employer-controller"

	"github.com/gin-gonic/gin" // Import Gin framework
)

func main() {
	// Create a new Gin router
	router := gin.Default()

	// Use the SignInHandler for the /login route
	router.POST("/signin", auth.SignInHandler)

	adminRoute := router.Group("/admin", admin.AuthMiddleware())
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

	employerRoute := router.Group("/employer", employer.AuthMiddleware())
	{
		employerRoute.POST("/jobcreate", employer.JobCreate)
	}

	// Run the server on port 8080
	router.Run(":8080")
}
