package employer

import (
	"database/sql"
	services "fresh-grad-jobs/services"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

// TODO: Create job ✅
// สร้างประกาศงานใหม่ที่นายจ้างต้องการรับสมัคร

// TODO: Delete job ✅
// ลบประกาศงานที่สร้างไว้ เช่น งานที่ปิดรับสมัครแล้ว

// TODO: Update job ✅
// แก้ไขข้อมูลประกาศงาน เช่น อัปเดตเงินเดือนหรือคุณสมบัติที่ต้องการ

// TODO: View job ✅
// ดูรายละเอียดประกาศงานที่สร้างหรือโพสต์ไว้

// TODO: View applications ✅
// ดูรายชื่อและรายละเอียดผู้สมัครงานที่สมัครเข้ามา

// Suggested enhancements

// TODO: Search/filter applicants ❌
// ค้นหาและกรองข้อมูลผู้สมัครงานตามเงื่อนไข เช่น ทักษะหรือประสบการณ์

// TODO: Save applicant profiles ❌
// บันทึกโปรไฟล์ผู้สมัครที่สนใจไว้เพื่อพิจารณาภายหลัง

// AuthMiddleware checks for employer role in the JWT and retrieves employer_id
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		// Log the incoming request
		log.Printf("Starting authentication middleware for request: %s %s", c.Request.Method, c.Request.URL.Path)

		// Check if Authorization header is present and valid
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Println("Authorization header missing or malformed")
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Authorization header missing or malformed"})
			c.Abort()
			return
		}

		// Extract the token from the header
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token and retrieve claims
		jwtClaims, err := services.ValidateJWT(token)
		if err != nil {
			log.Printf("Token validation failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Check if the role is "employer"
		role := jwtClaims.Role
		if role != "employer" {
			log.Printf("Insufficient permissions: role '%s' attempted access", role)
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Insufficient permissions"})
			c.Abort()
			return
		}

		// Log successful validation and role check
		log.Printf("Authentication successful for employer_id: %d", jwtClaims.ID)

		// Store employer_id in context for later use
		c.Set("employer_id", jwtClaims.ID)

		// Continue to the next middleware or handler
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

	// Log the request body for debugging
	log.Println("Received job creation request")

	// Bind the request body to the jobRequest struct
	if err := c.ShouldBindJSON(&jobRequest); err != nil {
		log.Printf("Error binding job creation request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format", "details": err.Error()})
		return
	}

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		log.Println("Employer ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found"})
		return
	}

	// Connect to the database
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	// Check if employer is approved
	var approved bool
	approvedQuery := "SELECT approved FROM users WHERE user_id=?"
	if err := db.QueryRow(approvedQuery, employerID).Scan(&approved); err != nil {
		log.Printf("Error checking employer approval status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error checking employer approval status"})
		return
	}

	if !approved {
		log.Printf("Employer %v is not approved", employerID)
		c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Employer is not approved"})
		return
	}

	// Prepare the query for job creation
	query := `INSERT INTO jobs (
		title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, max_experience,
		job_responsibility, qualification, benefits, job_description, location, posted_by,
		application_deadline, job_status, skills_required, job_level
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// Execute the query
	_, err = db.Exec(query,
		jobRequest.Title,
		employerID, // Use employer_id from context
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

	// Handle potential errors during job creation
	if err != nil {
		log.Printf("Failed to create job for employer %v: %v", employerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to create job", "details": err.Error()})
		return
	}

	// Job created successfully
	log.Printf("Job created successfully for employer %v", employerID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Job created successfully"})
}

// JobsUpdate handles job update requests
func JobsUpdate(c *gin.Context) {
	jobID := c.Param("job-id") // Get job ID from the URL parameters

	var jobRequest struct {
		Title               *string  `json:"title"`
		Job_Category        *string  `json:"job_category"`
		Job_Type            *string  `json:"job_type"` // Enum: Full-time, Contract
		Min_Salary          *float64 `json:"min_salary"`
		Max_Salary          *float64 `json:"max_salary"`
		Min_Experience      *int     `json:"min_experience"`
		Max_Experience      *int     `json:"max_experience"`
		Job_Responsibility  *string  `json:"job_responsibility"`
		Qualification       *string  `json:"qualification"`
		Benefits            *string  `json:"benefits"`
		Job_Description     *string  `json:"job_description"`
		Location            *string  `json:"location"`
		PostedBy            *string  `json:"posted_by"`
		ApplicationDeadline *string  `json:"application_deadline"`
		JobStatus           *string  `json:"job_status"`
		SkillsRequired      *string  `json:"skills_required"`
		JobLevel            *string  `json:"job_level"`
	}

	// Log the incoming update request
	log.Printf("Received job update request for job ID: %s", jobID)

	// Bind the JSON request to the jobRequest struct
	if err := c.ShouldBindJSON(&jobRequest); err != nil {
		log.Printf("Error binding update request for job ID %s: %v", jobID, err)
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format", "details": err.Error()})
		return
	}

	// Connect to the database
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error for job update (Job ID: %s): %v", jobID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection after updating job %s: %v", jobID, err)
		}
	}()

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		log.Printf("Employer ID not found in context for job update (Job ID: %s)", jobID)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found in context"})
		return
	}

	// Check if the job exists and belongs to the employer
	var jobExists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id = ? AND employer_id = ?)"
	if err := db.QueryRow(checkQuery, jobID, employerID).Scan(&jobExists); err != nil {
		log.Printf("Error checking job existence (Job ID: %s, Employer ID: %v): %v", jobID, employerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database query error"})
		return
	}

	if !jobExists {
		log.Printf("Job not found or not owned by employer (Job ID: %s, Employer ID: %v)", jobID, employerID)
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found or not your job"})
		return
	}

	// Prepare fields to update
	updateFields := []string{}
	updateValues := []interface{}{}

	if jobRequest.Title != nil {
		updateFields = append(updateFields, "title = ?")
		updateValues = append(updateValues, *jobRequest.Title)
	}
	if jobRequest.Job_Category != nil {
		updateFields = append(updateFields, "job_category = ?")
		updateValues = append(updateValues, *jobRequest.Job_Category)
	}
	if jobRequest.Job_Type != nil {
		updateFields = append(updateFields, "job_type = ?")
		updateValues = append(updateValues, *jobRequest.Job_Type)
	}
	if jobRequest.Min_Salary != nil {
		updateFields = append(updateFields, "min_salary = ?")
		updateValues = append(updateValues, *jobRequest.Min_Salary)
	}
	if jobRequest.Max_Salary != nil {
		updateFields = append(updateFields, "max_salary = ?")
		updateValues = append(updateValues, *jobRequest.Max_Salary)
	}
	if jobRequest.Min_Experience != nil {
		updateFields = append(updateFields, "min_experience = ?")
		updateValues = append(updateValues, *jobRequest.Min_Experience)
	}
	if jobRequest.Max_Experience != nil {
		updateFields = append(updateFields, "max_experience = ?")
		updateValues = append(updateValues, *jobRequest.Max_Experience)
	}
	if jobRequest.Job_Responsibility != nil {
		updateFields = append(updateFields, "job_responsibility = ?")
		updateValues = append(updateValues, *jobRequest.Job_Responsibility)
	}
	if jobRequest.Qualification != nil {
		updateFields = append(updateFields, "qualification = ?")
		updateValues = append(updateValues, *jobRequest.Qualification)
	}
	if jobRequest.Benefits != nil {
		updateFields = append(updateFields, "benefits = ?")
		updateValues = append(updateValues, *jobRequest.Benefits)
	}
	if jobRequest.Job_Description != nil {
		updateFields = append(updateFields, "job_description = ?")
		updateValues = append(updateValues, *jobRequest.Job_Description)
	}
	if jobRequest.Location != nil {
		updateFields = append(updateFields, "location = ?")
		updateValues = append(updateValues, *jobRequest.Location)
	}
	if jobRequest.PostedBy != nil {
		updateFields = append(updateFields, "posted_by = ?")
		updateValues = append(updateValues, *jobRequest.PostedBy)
	}
	if jobRequest.ApplicationDeadline != nil {
		updateFields = append(updateFields, "application_deadline = ?")
		updateValues = append(updateValues, *jobRequest.ApplicationDeadline)
	}
	if jobRequest.JobStatus != nil {
		updateFields = append(updateFields, "job_status = ?")
		updateValues = append(updateValues, *jobRequest.JobStatus)
	}
	if jobRequest.SkillsRequired != nil {
		updateFields = append(updateFields, "skills_required = ?")
		updateValues = append(updateValues, *jobRequest.SkillsRequired)
	}
	if jobRequest.JobLevel != nil {
		updateFields = append(updateFields, "job_level = ?")
		updateValues = append(updateValues, *jobRequest.JobLevel)
	}

	// Ensure there are fields to update
	if len(updateFields) == 0 {
		log.Printf("No fields to update for job ID %s", jobID)
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "No fields to update"})
		return
	}

	// Build the update query
	updateQuery := "UPDATE jobs SET " + strings.Join(updateFields, ", ") + " WHERE job_id = ? AND employer_id = ?"
	updateValues = append(updateValues, jobID, employerID) // Add jobID and employerID to the query

	// Execute the update query
	if _, err := db.Exec(updateQuery, updateValues...); err != nil {
		log.Printf("Failed to update job (Job ID: %s, Employer ID: %v): %v", jobID, employerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to update job", "details": err.Error()})
		return
	}

	// Successfully updated the job
	log.Printf("Job updated successfully (Job ID: %s, Employer ID: %v)", jobID, employerID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Job updated successfully"})
}

// JobsDelete handles the deletion of a job by ID
func JobsDelete(c *gin.Context) {
	jobID := c.Param("job-id")

	// Log the incoming delete request
	log.Printf("Received request to delete job with ID: %s", jobID)

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		log.Printf("Employer ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found in context"})
		return
	}

	// Check if the job exists and belongs to the employer
	var jobExists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id = ? AND employer_id = ?)"
	err = db.QueryRow(checkQuery, jobID, employerID).Scan(&jobExists)
	if err != nil {
		log.Printf("Error querying job existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	if !jobExists {
		log.Printf("Job not found or does not belong to employer (Job ID: %s, Employer ID: %v)", jobID, employerID)
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Job not found or not owned by employer",
		})
		return
	}

	// Begin a transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error starting transaction",
		})
		return
	}

	// Perform the job deletion within the transaction
	deleteQuery := "DELETE FROM jobs WHERE job_id = ? AND employer_id = ?"
	_, err = tx.Exec(deleteQuery, jobID, employerID)
	if err != nil {
		log.Printf("Error deleting job (Job ID: %s): %v", jobID, err)
		tx.Rollback() // Roll back the transaction if something goes wrong
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error deleting job",
		})
		return
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error committing transaction",
		})
		return
	}

	// Log success and return response
	log.Printf("Job deleted successfully (Job ID: %s, Employer ID: %v)", jobID, employerID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Job deleted successfully",
	})
}

// JobsViews retrieves all jobs or a specific job by ID from the database and returns them as JSON
func JobsViews(c *gin.Context) {
	jobID := c.Param("job-id")

	// Log the request
	log.Printf("Received request to view jobs. Job ID: %s", jobID)

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}()

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		log.Printf("Employer ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Employer ID not found in context",
		})
		return
	}

	// Define the Job struct
	type Job struct {
		ID                  string  `json:"job_id"`
		Title               string  `json:"title"`
		EmployerID          string  `json:"employer_id"`
		JobCategory         string  `json:"job_category"`
		JobType             string  `json:"job_type"`
		MinSalary           float64 `json:"min_salary"`
		MaxSalary           float64 `json:"max_salary"`
		MinExperience       int     `json:"min_experience"`
		MaxExperience       int     `json:"max_experience"`
		JobResponsibility   string  `json:"job_responsibility"`
		Qualification       string  `json:"qualification"`
		Benefits            string  `json:"benefits"`
		JobDescription      string  `json:"job_description"`
		Approved            bool    `json:"approved"`
		CreatedAt           string  `json:"created_at"`
		Location            string  `json:"location"`
		PostedBy            string  `json:"posted_by"`
		ApplicationDeadline string  `json:"application_deadline"`
		JobStatus           string  `json:"job_status"`
		SkillsRequired      string  `json:"skills_required"`
		JobLevel            string  `json:"job_level"`
	}

	// Prepare the query
	var query string
	var args []interface{}

	if jobID == "" {
		// Fetch all jobs for the employer
		query = `
									SELECT job_id, title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, 
																max_experience, job_responsibility, qualification, benefits, job_description, approved, 
																created_at, location, posted_by, application_deadline, job_status, skills_required, job_level 
									FROM jobs 
									WHERE employer_id = ?
					`
		args = append(args, employerID)
	} else {
		// Fetch specific job for the employer
		query = `
									SELECT job_id, title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, 
																max_experience, job_responsibility, qualification, benefits, job_description, approved, 
																created_at, location, posted_by, application_deadline, job_status, skills_required, job_level 
									FROM jobs 
									WHERE job_id = ? AND employer_id = ?
					`
		args = append(args, jobID, employerID)
	}

	// Execute the query
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Query execution error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Query execution error",
		})
		return
	}
	defer rows.Close()

	// Process the results
	var jobs []Job
	for rows.Next() {
		var job Job
		if err := rows.Scan(
			&job.ID, &job.Title, &job.EmployerID, &job.JobCategory, &job.JobType, &job.MinSalary,
			&job.MaxSalary, &job.MinExperience, &job.MaxExperience, &job.JobResponsibility, &job.Qualification,
			&job.Benefits, &job.JobDescription, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy,
			&job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel,
		); err != nil {
			log.Printf("Row scan error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  "error",
				"message": "Row scan error",
			})
			return
		}
		jobs = append(jobs, job)
	}

	// Check for errors after scanning
	if err := rows.Err(); err != nil {
		log.Printf("Rows error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error processing rows",
		})
		return
	}

	// Return the results
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   jobs,
	})
}

// ApplicationViews for employers to see which fresh graduates have applied for the job posting
func ApplicationViews(c *gin.Context) {
	applicationID := c.Param("application-id")
	jobID := c.Param("job-id")

	// Log request for viewing applications
	log.Printf("ApplicationViews called with applicationID: %s, jobID: %s", applicationID, jobID)

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing DB connection: %v", err)
		}
	}()

	// Struct to hold application data
	type Application struct {
		ApplicationID      int    `json:"application_id"`
		JobID              int    `json:"job_id"`
		FreshGradProfileID int    `json:"fresh_grad_profile_id"`
		FreshGradResume    string `json:"resume_file_link"`
	}

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		log.Printf("Employer ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Employer ID not found in context",
		})
		return
	}

	// If no application ID is provided, fetch all applications for a job
	if applicationID == "" {
		log.Printf("Fetching all applications for jobID: %s", jobID)

		query := `
									SELECT a.application_id, a.job_id, a.freshgradprofile_id, f.resume_file_link
									FROM applications a 
									INNER JOIN jobs j ON a.job_id = j.job_id 
									INNER JOIN freshgradprofiles f ON a.freshgradprofile_id = f.freshgradprofile_id
									WHERE j.employer_id = ? AND a.job_id = ?
					`

		rows, err := db.Query(query, employerID, jobID)
		if err != nil {
			log.Printf("Query execution error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Query execution error"})
			return
		}
		defer rows.Close()

		var applications []Application

		for rows.Next() {
			var application Application
			if err := rows.Scan(&application.ApplicationID, &application.JobID, &application.FreshGradProfileID, &application.FreshGradResume); err != nil {
				log.Printf("Row scan error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
				return
			}
			applications = append(applications, application)
		}

		// Check for any errors during row iteration
		if err := rows.Err(); err != nil {
			log.Printf("Rows iteration error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error processing applications"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   applications,
		})

	} else {
		// Fetch specific application based on applicationID
		log.Printf("Fetching application with applicationID: %s", applicationID)

		query := `
									SELECT a.application_id, a.job_id, a.freshgradprofile_id, f.resume_file_link
									FROM applications a 
									INNER JOIN jobs j ON a.job_id = j.job_id 
									INNER JOIN freshgradprofiles f ON a.freshgradprofile_id = f.freshgradprofile_id
									WHERE a.application_id = ? AND j.employer_id = ? AND a.job_id = ?
					`

		row := db.QueryRow(query, applicationID, employerID, jobID)

		var application Application
		if err := row.Scan(&application.ApplicationID, &application.JobID, &application.FreshGradProfileID, &application.FreshGradResume); err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Application not found for applicationID: %s", applicationID)
				c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Application not found"})
			} else {
				log.Printf("Row scan error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   application,
		})
	}
}
