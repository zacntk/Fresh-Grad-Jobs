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
		adminRoute.DELETE("/jobs/delete/:job-id", admin.JobsDelete)
		// Route for retrieving all jobs
		adminRoute.GET("/jobs/views", admin.JobsViews) // Updated path
		// Route for retrieving specific job
		adminRoute.GET("/jobs/views/:job-id", admin.JobsViews)
	}

	employerRoute := router.Group("/employer", employer.AuthMiddleware())
	{
		// Route for creating job
		employerRoute.POST("/jobcreate", employer.JobCreate)
		// Route for deleting a job by ID
		employerRoute.DELETE("/jobs/delete/:job-id", employer.JobsDelete)
		// Route for updating a job by ID
		employerRoute.POST("/jobs/update/:job-id", employer.JobsUpdate)
		// Route for retrieving all jobs
		employerRoute.GET("/jobs/views/", employer.JobsViews)
		// Route for retrieving specific job
		employerRoute.GET("/jobs/views/:job-id", employer.JobsViews)
		// Route for retrieving all application of job
		employerRoute.GET("/jobs/views/:job-id/application/views", employer.ApplicationViews)
		// Route for retrieving specific application of job
		employerRoute.GET("/jobs/views/:job-id/application/views/:application-id", employer.ApplicationViews)
	}

	// Run the server on port 8080
	router.Run(":8080")
}
