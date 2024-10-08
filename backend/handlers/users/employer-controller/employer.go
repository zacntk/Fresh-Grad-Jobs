package employer

import (
	"fresh-grad-jobs/services"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware checks for employer role in the JWT and retrieves employer_id
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Authorization header missing or malformed"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token and get the claims
		jwtClaims, err := services.ValidateJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Check for employer role
		role := jwtClaims.Role
		if role != "employer" {
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Insufficient permissions"})
			c.Abort()
			return
		}

		// Store employer_id in context for later use
		c.Set("employer_id", jwtClaims.ID)

		c.Next()
	}
}

// JobCreate handles job creation requests
func JobCreate(c *gin.Context) {
	var jobRequest struct {
		Title               string  `json:"title" binding:"required"`
		Job_Category        string  `json:"job_category" binding:"required"`
		Job_Type            string  `json:"job_type" binding:"required"` // Enum: Full-time, Contract
		Min_Salary          float64 `json:"min_salary" binding:"required"`
		Max_Salary          float64 `json:"max_salary" binding:"required"`
		Min_Experience      int     `json:"min_experience" binding:"required"`
		Max_Experience      int     `json:"max_experience" binding:"required"`
		Job_Responsibility  string  `json:"job_responsibility" binding:"required"`
		Qualification       string  `json:"qualification" binding:"required"`
		Benefits            string  `json:"benefits" binding:"required"`
		Job_Description     string  `json:"job_description" binding:"required"`
		Location            string  `json:"location" binding:"required"`
		PostedBy            string  `json:"posted_by" binding:"required"`
		ApplicationDeadline string  `json:"application_deadline" binding:"required"`
		JobStatus           string  `json:"job_status" binding:"required"`
		SkillsRequired      string  `json:"skills_required" binding:"required"`
		JobLevel            string  `json:"job_level" binding:"required"`
	}

	// Bind the request
	if err := c.ShouldBindJSON(&jobRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format", "details": err.Error()})
		return
	}

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found in context"})
		return
	}

	// Connect to the database
	db, err := services.ConnectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer db.Close() // Ensure the database connection is closed

	// Corrected SQL query with all relevant fields
	query := `INSERT INTO jobs (
		title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, max_experience,
		job_responsibility, qualification, benefits, job_description, location, posted_by,
		application_deadline, job_status, skills_required, job_level
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// Execute the query with values from the struct
	_, err = db.Exec(query,
		jobRequest.Title,
		employerID, // Use the employer_id from the context
		jobRequest.Job_Category,
		jobRequest.Job_Type,
		jobRequest.Min_Salary,
		jobRequest.Max_Salary,
		jobRequest.Min_Experience,
		jobRequest.Max_Experience,
		jobRequest.Job_Responsibility,
		jobRequest.Qualification,
		jobRequest.Benefits,
		jobRequest.Job_Description,
		jobRequest.Location,
		jobRequest.PostedBy,
		jobRequest.ApplicationDeadline,
		jobRequest.JobStatus,
		jobRequest.SkillsRequired,
		jobRequest.JobLevel,
	)

	// Handle possible errors during query execution
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to create job", "details": err.Error()})
		return
	}

	// Respond with success
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Job created successfully"})
}
