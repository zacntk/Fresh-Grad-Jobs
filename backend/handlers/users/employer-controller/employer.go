package employer

import (
	"database/sql"
	services "fresh-grad-jobs/services"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
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

	var approved bool
	approvedQuery := "SELECT approved FROM users WHERE id=?"
	err = db.QueryRow(approvedQuery, employerID).Scan(&approved)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error checking employer approval status"})
		return
	}

	if !approved {
		c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Employer is not approved"})
		return
	}

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

	// Bind the request
	if err := c.ShouldBindJSON(&jobRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format", "details": err.Error()})
		return
	}

	// Connect to the database
	db, err := services.ConnectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer db.Close() // Ensure the database connection is closed

	// Retrieve employer_id from the context
	var exists bool
	employerID, exists := c.Get("employer_id")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found in context"})
		return
	}

	// Check if the job exists
	checkQuery := "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id = ? AND employer_id = ?)"
	err = db.QueryRow(checkQuery, jobID, employerID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database query error"})
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found or not your job"})
		return
	}

	// Prepare update fields
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

	// Check if there are fields to update
	if len(updateFields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "No fields to update"})
		return
	}

	// Create the update query string
	updateQuery := "UPDATE jobs SET " + strings.Join(updateFields, ", ") + " WHERE job_id = ? AND employer_id = ?"
	updateValues = append(updateValues, jobID, employerID) // Add job ID for the WHERE clause

	// Execute the update query
	_, err = db.Exec(updateQuery, updateValues...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Failed to update job", "details": err.Error()})
		return
	}

	// Respond with success
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Job updated successfully"})
}

// JobsDelete handles the deletion of a job by ID
func JobsDelete(c *gin.Context) {
	jobID := c.Param("job-id")

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer db.Close()

	// Check if job exists
	var jobExists bool
	query := "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id = ?)"
	err = db.QueryRow(query, jobID).Scan(&jobExists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	if !jobExists {
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Job not found",
		})
		return
	}

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found in context"})
		return
	}

	deleteQuery := "DELETE FROM jobs WHERE job_id = ? AND employer_id = ?"
	_, err = db.Exec(deleteQuery, jobID, employerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error deleting job",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Job deleted successfully",
	})
}

// JobsViews retrieves all jobs or a specific job by ID from the database and returns them as JSON
func JobsViews(c *gin.Context) {
	jobID := c.Param("job-id")

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer db.Close()

	// Retrieve employer_id from the context
	employerID, exists := c.Get("employer_id")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Employer ID not found in context",
		})
		return
	}

	// Job represents the structure of a job listing
	type Job struct {
		ID                  string  `json:"job_id"`               // รหัสงาน
		Title               string  `json:"title"`                // ชื่องาน
		EmployerID          string  `json:"employer_id"`          // รหัสนายจ้าง
		JobCategory         string  `json:"job_category"`         // หมวดหมู่งาน
		JobType             string  `json:"job_type"`             // ประเภทงาน (งานประจำ, งานสัญญาจ้าง)
		MinSalary           float64 `json:"min_salary"`           // เงินเดือนขั้นต่ำ
		MaxSalary           float64 `json:"max_salary"`           // เงินเดือนสูงสุด
		MinExperience       int     `json:"min_experience"`       // ประสบการณ์ขั้นต่ำ (ปี)
		MaxExperience       int     `json:"max_experience"`       // ประสบการณ์สูงสุด (ปี)
		JobResponsibility   string  `json:"job_responsibility"`   // ความรับผิดชอบของงาน
		Qualification       string  `json:"qualification"`        // คุณสมบัติที่ต้องการ
		Benefits            string  `json:"benefits"`             // สวัสดิการ
		JobDescription      string  `json:"job_description"`      // รายละเอียดงาน
		Approved            bool    `json:"approved"`             // สถานะการอนุมัติ
		CreatedAt           string  `json:"created_at"`           // วันเวลาที่สร้าง
		Location            string  `json:"location"`             // สถานที่ทำงาน
		PostedBy            string  `json:"posted_by"`            // ผู้โพสต์งาน
		ApplicationDeadline string  `json:"application_deadline"` // วันหมดเขตการสมัคร
		JobStatus           string  `json:"job_status"`           // สถานะงาน (เปิดรับสมัคร, ปิดรับสมัคร)
		SkillsRequired      string  `json:"skills_required"`      // ทักษะที่ต้องการ
		JobLevel            string  `json:"job_level"`            // ระดับงาน (Junior, Mid-level, Senior)
	}

	// If jobID is empty, fetch all jobs for the employer
	if jobID == "" {
		query := `
			SELECT job_id, title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, 
			max_experience, job_responsibility, qualification, benefits, job_description, approved, 
			created_at, location, posted_by, application_deadline, job_status, skills_required, job_level 
			FROM jobs WHERE employer_id = ?
		`

		rows, err := db.Query(query, employerID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Query execution error"})
			return
		}
		defer rows.Close()

		var jobs []Job

		for rows.Next() {
			var job Job
			if err := rows.Scan(
				&job.ID, &job.Title, &job.EmployerID, &job.JobCategory, &job.JobType, &job.MinSalary,
				&job.MaxSalary, &job.MinExperience, &job.MaxExperience, &job.JobResponsibility, &job.Qualification,
				&job.Benefits, &job.JobDescription, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy,
				&job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel,
			); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
				return
			}
			jobs = append(jobs, job)
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   jobs,
		})

	} else {
		// If jobID is provided, fetch the specific job for the employer
		query := `
			SELECT job_id, title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, 
			max_experience, job_responsibility, qualification, benefits, job_description, approved, 
			created_at, location, posted_by, application_deadline, job_status, skills_required, job_level 
			FROM jobs WHERE job_id = ? AND employer_id = ?
		`

		row := db.QueryRow(query, jobID, employerID)

		var job Job
		if err := row.Scan(
			&job.ID, &job.Title, &job.EmployerID, &job.JobCategory, &job.JobType, &job.MinSalary,
			&job.MaxSalary, &job.MinExperience, &job.MaxExperience, &job.JobResponsibility, &job.Qualification,
			&job.Benefits, &job.JobDescription, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy,
			&job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel,
		); err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   job,
		})
	}
}

// ApplicationViews for employers to see which fresh graduates have applied for the job posting
func ApplicationViews(c *gin.Context) {
	applicationID := c.Param("application-id")
	jobID := c.Param("job-id")

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer db.Close()

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
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Employer ID not found in context"})
		return
	}

	if applicationID == "" {
		// Prepare the SQL query with a JOIN to get all applications for a specific job
		query := `
			SELECT a.application_id, a.job_id, a.freshgradprofile_id, f.resume_file_link
			FROM applications a 
			INNER JOIN jobs j ON a.job_id = j.job_id 
			INNER JOIN freshgradprofiles f ON a.freshgradprofile_id = f.freshgradprofile_id
			WHERE j.employer_id = ? AND a.job_id = ?`

		// Execute the query with employerID and jobID
		rows, err := db.Query(query, employerID, jobID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Query execution error"})
			return
		}
		defer rows.Close()

		var applications []Application // Initialize an empty slice of applications

		for rows.Next() {
			var application Application
			if err := rows.Scan(&application.ApplicationID, &application.JobID, &application.FreshGradProfileID, &application.FreshGradResume); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
				return
			}
			applications = append(applications, application)
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   applications,
		})

	} else {
		// Query for a specific application by application ID
		query := `
			SELECT a.application_id, a.job_id, a.freshgradprofile_id, f.resume_file_link
			FROM applications a 
			INNER JOIN jobs j ON a.job_id = j.job_id 
			INNER JOIN freshgradprofiles f ON a.freshgradprofile_id = f.freshgradprofile_id
			WHERE a.application_id = ? AND j.employer_id = ? AND a.job_id = ?`

		row := db.QueryRow(query, applicationID, employerID, jobID)

		var application Application
		if err := row.Scan(&application.ApplicationID, &application.JobID, &application.FreshGradProfileID, &application.FreshGradResume); err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Application not found"})
			} else {
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
