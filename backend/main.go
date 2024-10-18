package main

import (
	"context"
	admin "fresh-grad-jobs/handlers/users/admin-controller"
	auth "fresh-grad-jobs/handlers/users/auth"
	employer "fresh-grad-jobs/handlers/users/employer-controller"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
)

// TODO: CORS

func main() {
	// Create a new Gin router
	router := gin.Default()

	// Use the SignInHandler for the /signin route
	router.POST("/signin", auth.SignInHandler)

	// Admin routes
	adminRoute := router.Group("/admin", admin.AuthMiddleware())
	{
		adminRoute.POST("/users/approve/:user-id", admin.UserApprove)
		adminRoute.POST("/users/suspend/:user-id", admin.UserSuspend)
		adminRoute.DELETE("/users/delete/:user-id", admin.UserDelete)
		adminRoute.GET("/users", admin.UserViews)
		adminRoute.GET("/users/:user-id", admin.UserViews)
		adminRoute.POST("/jobs/approve/:job-id", admin.JobsApprove)
		adminRoute.DELETE("/jobs/delete/:job-id", admin.JobsDelete)
		adminRoute.GET("/jobs", admin.JobsViews)
		adminRoute.GET("/jobs/:job-id", admin.JobsViews)
	}

	// Employer routes
	employerRoute := router.Group("/employer", employer.AuthMiddleware())
	{
		employerRoute.POST("/jobs/create", employer.JobCreate)
		employerRoute.DELETE("/jobs/delete/:job-id", employer.JobsDelete)
		employerRoute.PUT("/jobs/update/:job-id", employer.JobsUpdate)
		employerRoute.GET("/jobs", employer.JobsViews)
		employerRoute.GET("/jobs/:job-id", employer.JobsViews)
		employerRoute.GET("/jobs/:job-id/applications", employer.ApplicationViews)
		employerRoute.GET("/jobs/:job-id/applications/:application-id", employer.ApplicationViews)
	}

	// Get port from environment variable or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Run the server in a goroutine to enable graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Set up a signal channel to listen for shutdown signals (like Ctrl+C)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	<-quit // This will block until a signal is received

	// Gracefully shutdown the server, waiting for 5 seconds for ongoing processes
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}
