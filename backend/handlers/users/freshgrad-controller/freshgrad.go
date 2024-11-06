package freshGrad

import (
	"fresh-grad-jobs/services"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// TODO: View job ❌
// ดูประกาศงานที่มีอยู่ในระบบ

// TODO: Apply for job ❌
// สมัครงานที่สนใจจากประกาศงานที่ดู

// TODO: View applied jobs ❌
// ดูรายการงานที่เคยสมัครไปแล้ว และติดตามสถานะการสมัคร

// TODO: Update profile ❌
// แก้ไขหรืออัปเดตโปรไฟล์ส่วนตัว เช่น ประวัติการศึกษา, ทักษะ, หรือประวัติการทำงาน

// Suggested enhancements

// TODO: Save jobs ❌
// บันทึกงานที่สนใจไว้เพื่อสมัครภายหลัง

// TODO: Track application status ❌
// ติดตามสถานะการสมัครงาน เช่น อยู่ระหว่างพิจารณาหรือถูกเรียกสัมภาษณ์

// TODO: Job alerts ❌
// รับการแจ้งเตือนเมื่อมีงานใหม่ที่ตรงกับทักษะหรือความสนใจของตน

// AuthMiddleware checks for freshGrad role in the JWT and retrieves frashgrad_id
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

		// Check if the role is "freshGrad"
		role := jwtClaims.Role
		if role != "freshGrad" {
			log.Printf("Insufficient permissions: role '%s' attempted access", role)
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Insufficient permissions"})
			c.Abort()
			return
		}

		// Log successful validation and role check
		log.Printf("Authentication successful for freshGrad_id: %d", jwtClaims.ID)

		// Store freshGrad_id in context for later use
		c.Set("freshGrad_id", jwtClaims.ID)

		// Continue to the next middleware or handler
		c.Next()
	}
}

// JobViews retrieves all jobs or a specific job by ID and returns them as JSON
func JobViews(c *gin.Context) {
	jobID := c.Param("job-id")
	log.Printf("Received request to view jobs. Job ID: %s", jobID)

	// Centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer db.Close()

	// Retrieve freshGrad ID
	freshGradID, exists := c.Get("freshGrad_id")
	if !exists {
		log.Printf("freshGrad ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "freshGrad ID not found"})
		return
	}

	// Check freshGrad's approval status and suspension
	var isApproved, isSuspended bool
	if err := db.QueryRow("SELECT approved, suspended FROM users WHERE user_id=?", freshGradID).Scan(&isApproved, &isSuspended); err != nil {
		log.Printf("Error checking approval status for freshGrad %v: %v", freshGradID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Error checking approval status"})
		return
	}
	if !isApproved {
		c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Account not approved"})
		return
	}
	if isSuspended {
		c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Account is suspended"})
		return
	}

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

	// Prepare base query
	var query string
	var args []interface{}

	if jobID == "" {
		query = "SELECT job_id, title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, " +
			"max_experience, job_responsibility, qualification, benefits, job_description, approved, created_at, " +
			"location, posted_by, application_deadline, job_status, skills_required, job_level FROM jobs WHERE 1=1"

		// Append filters conditionally
		if jobType := c.Query("job_type"); jobType != "" {
			query += " AND job_type = ?"
			args = append(args, jobType)
		}
		if jobCategory := c.Query("job_category"); jobCategory != "" {
			query += " AND job_category = ?"
			args = append(args, jobCategory)
		}
		if minSalary := c.Query("min_salary"); minSalary != "" {
			query += " AND min_salary >= ?"
			args = append(args, minSalary)
		}
		if maxSalary := c.Query("max_salary"); maxSalary != "" {
			query += " AND max_salary <= ?"
			args = append(args, maxSalary)
		}
		if minExperience := c.Query("min_experience"); minExperience != "" {
			query += " AND min_experience >= ?"
			args = append(args, minExperience)
		}
		if maxExperience := c.Query("max_experience"); maxExperience != "" {
			query += " AND max_experience <= ?"
			args = append(args, maxExperience)
		}
		if location := c.Query("location"); location != "" {
			query += " AND location = ?"
			args = append(args, location)
		}
		if approvedFilter := c.Query("approved"); approvedFilter != "" {
			query += " AND approved = ?"
			if approvedFilter == "true" {
				args = append(args, true)
			} else {
				args = append(args, false)
			}
		}
		if createdAfter := c.Query("created_after"); createdAfter != "" {
			query += " AND created_at >= ?"
			args = append(args, createdAfter)
		}
		if createdBefore := c.Query("created_before"); createdBefore != "" {
			query += " AND created_at <= ?"
			args = append(args, createdBefore)
		}
	} else {
		query = "SELECT job_id, title, employer_id, job_category, job_type, min_salary, max_salary, min_experience, " +
			"max_experience, job_responsibility, qualification, benefits, job_description, approved, created_at, " +
			"location, posted_by, application_deadline, job_status, skills_required, job_level FROM jobs WHERE job_id = ?"
		args = append(args, jobID)
	}

	// Execute query
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Query execution error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Query execution error"})
		return
	}
	defer rows.Close()

	// Process query results
	var jobs []Job
	for rows.Next() {
		var job Job
		if err := rows.Scan(
			&job.ID, &job.Title, &job.EmployerID, &job.JobCategory, &job.JobType, &job.MinSalary, &job.MaxSalary,
			&job.MinExperience, &job.MaxExperience, &job.JobResponsibility, &job.Qualification, &job.Benefits,
			&job.JobDescription, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy, &job.ApplicationDeadline,
			&job.JobStatus, &job.SkillsRequired, &job.JobLevel,
		); err != nil {
			log.Printf("Row scan error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
			return
		}
		jobs = append(jobs, job)
	}

	// Final response
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": jobs})
}
