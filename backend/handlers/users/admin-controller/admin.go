package admin

import (
	"database/sql"
	services "fresh-grad-jobs/services"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

// TODO: Approve user ✅
// อนุมัติผู้ใช้ที่สมัครเข้ามาใหม่ ให้สามารถใช้งานระบบได้

// TODO: Delete user ✅
// ลบผู้ใช้ออกจากระบบ เช่น นายจ้างหรือนักศึกษาจบใหม่ที่ทำผิดกฎ

// TODO: View user ✅
// ดูรายละเอียดข้อมูลผู้ใช้ เช่น ข้อมูลส่วนตัว, โปรไฟล์, ประวัติการใช้งาน

// TODO: Approve job ✅
// อนุมัติประกาศงานที่นายจ้างสร้างขึ้นให้แสดงในระบบ

// TODO: Delete job ✅
// ลบประกาศงานที่ไม่เหมาะสม หรือประกาศงานที่ต้องการลบออกจากระบบ

// TODO: View job ✅
// ดูประกาศงานที่โพสต์ในระบบ รวมถึงรายละเอียดต่าง ๆ ของงาน

// Suggested enhancements

// TODO: Suspend user ✅
// ระงับการใช้งานของผู้ใช้ชั่วคราวในกรณีที่มีการละเมิดกฎ

// TODO: Search/filter users/jobs ✅
// ค้นหาและกรองข้อมูลผู้ใช้หรือประกาศงานตามเงื่อนไขที่กำหนด เช่น ตามตำแหน่งงาน หรือชื่อผู้ใช้

// TODO: Analytics dashboard ❌
// แดชบอร์ดวิเคราะห์ข้อมูล เช่น การดูสถิติจำนวนประกาศงาน, การใช้งานของผู้ใช้

// AuthMiddleware checks for admin role
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Printf("Unauthorized access attempt: Missing or malformed Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Authorization header missing or malformed"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token and get the claims
		jwtClaims, err := services.ValidateJWT(token)
		if err != nil {
			log.Printf("Invalid token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Check for employer role
		role := jwtClaims.Role
		if role != "admin" {
			log.Printf("Insufficient permissions: User with role '%s' attempted to access admin route", role)
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Insufficient permissions"})
			c.Abort()
			return
		}

		log.Printf("Admin access granted for user with role '%s'", role)
		c.Next()
	}
}

// UserApprove handles the approval of a user by ID
func UserApprove(c *gin.Context) {
	userID := c.Param("user-id")
	log.Printf("Attempting to approve user with ID: %s", userID)

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
	defer db.Close()

	// Check if user exists and get their approval status
	var isApproved bool
	query := "SELECT approved FROM users WHERE user_id = ?"
	err = db.QueryRow(query, userID).Scan(&isApproved)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found: %s", userID)
			c.JSON(http.StatusNotFound, gin.H{
				"status":  "error",
				"message": "User not found",
			})
			return
		}
		log.Printf("Database query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	// Check if the user is already approved
	if isApproved {
		log.Printf("User %s is already approved", userID)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "User is already approved",
		})
		return
	}

	// Perform approval logic - update the approved status
	updateQuery := "UPDATE users SET approved = ? WHERE user_id = ?"
	_, err = db.Exec(updateQuery, true, userID)
	if err != nil {
		log.Printf("Error updating user approval status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error updating user approval status",
		})
		return
	}

	log.Printf("User %s approved successfully", userID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User approved successfully",
	})
}

// UserSuspend handles the suspension of a user by ID
func UserSuspend(c *gin.Context) {
	userID := c.Param("user-id")
	log.Printf("Attempting to suspend user with ID: %s", userID)

	// Use centralized DB connection
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Failed to connect to database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer db.Close()

	// Check if user exists and retrieve suspension status
	var isSuspended bool
	query := "SELECT suspended FROM users WHERE user_id = ?"
	err = db.QueryRow(query, userID).Scan(&isSuspended)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User with ID %s not found", userID)
			c.JSON(http.StatusNotFound, gin.H{
				"status":  "error",
				"message": "User not found",
			})
			return
		}
		log.Printf("Error querying user suspension status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error querying user suspension status",
		})
		return
	}

	// Check if the user is already suspended
	if isSuspended {
		log.Printf("User with ID %s is already suspended", userID)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "User is already suspended",
		})
		return
	}

	// Update suspension status
	updateQuery := "UPDATE users SET suspended = ? WHERE user_id = ?"
	_, err = db.Exec(updateQuery, true, userID)
	if err != nil {
		log.Printf("Error updating suspension status for user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error updating user suspension status",
		})
		return
	}

	log.Printf("User with ID %s suspended successfully", userID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User suspended successfully",
	})
}

// UserDelete handles the deletion of a user by ID
func UserDelete(c *gin.Context) {
	userID := c.Param("user-id")
	log.Printf("Attempting to delete user with ID: %s", userID)

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
	defer db.Close()

	// Check if user exists
	var userExists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE user_id = ?)"
	err = db.QueryRow(query, userID).Scan(&userExists)
	if err != nil {
		log.Printf("Database query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	if !userExists {
		log.Printf("User not found: %s", userID)
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "User not found",
		})
		return
	}

	// Perform deletion logic
	deleteQuery := "DELETE FROM users WHERE user_id = ?"
	_, err = db.Exec(deleteQuery, userID)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error deleting user",
		})
		return
	}

	log.Printf("User %s deleted successfully", userID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User deleted successfully",
	})
}

// UserViews retrieves all jobs or a specific user by ID from the database and returns them as JSON
func UserViews(c *gin.Context) {
	// Get role and user-id from query parameters
	role := c.Query("role")      // Role is now retrieved as a query parameter
	userID := c.Param("user-id") // Keep user-id as a path parameter for individual user lookup

	// Additional filters
	emailFilter := c.Query("email")            // Optional email filter
	approvedFilter := c.Query("approved")      // Optional approval status filter
	suspendedFilter := c.Query("suspended")    // Optional suspension status filter
	createdAfter := c.Query("created_after")   // Optional created_at filter (after a certain date)
	createdBefore := c.Query("created_before") // Optional created_at filter (before a certain date)

	limit := c.DefaultQuery("limit", "10")  // Pagination limit (default to 10)
	offset := c.DefaultQuery("offset", "0") // Pagination offset (default to 0)

	log.Printf("Retrieving users. Role: %s, UserID: %s", role, userID)

	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database connection error",
		})
		return
	}
	defer db.Close()

	// Base query
	var query string
	var args []interface{}

	// Adjust query for filtering based on userID or all users
	if userID == "" {
		if role == "" || role == "all" {
			query = "SELECT user_id, email, role, approved, suspended, created_at FROM users WHERE role != 'admin'"
		} else {
			query = "SELECT user_id, email, role, approved, suspended, created_at FROM users WHERE role = ? AND role != 'admin'"
			args = append(args, role)
		}
	} else {
		if role == "" || role == "all" {
			query = "SELECT user_id, email, role, approved, suspended, created_at FROM users WHERE user_id = ? AND role != 'admin'"
			args = append(args, userID)
		} else {
			query = "SELECT user_id, email, role, approved, suspended, created_at FROM users WHERE role = ? AND user_id = ? AND role != 'admin'"
			args = append(args, role, userID)
		}
	}

	// Apply filters (dynamically add WHERE clauses)
	if emailFilter != "" {
		query += " AND email LIKE ?"
		args = append(args, "%"+emailFilter+"%") // Partial match for email
	}

	if approvedFilter != "" {
		query += " AND approved = ?"
		if approvedFilter == "true" {
			args = append(args, true)
		} else {
			args = append(args, false)
		}
	}

	if suspendedFilter != "" {
		query += " AND suspended = ?"
		// Interpret "true" or "false" as actual boolean values
		if suspendedFilter == "true" {
			args = append(args, true)
		} else {
			args = append(args, false)
		}
	}

	if createdAfter != "" {
		query += " AND created_at >= ?"
		args = append(args, createdAfter)
	}

	if createdBefore != "" {
		query += " AND created_at <= ?"
		args = append(args, createdBefore)
	}

	// Add pagination to the query
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	// Execute the query
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Database query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}
	defer rows.Close()

	var users []struct {
		ID        string `json:"user_id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		Approved  bool   `json:"approved"`
		Suspended bool   `json:"suspended"`
		CreatedAt string `json:"created_at"`
	}

	for rows.Next() {
		var user struct {
			ID        string `json:"user_id"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			Approved  bool   `json:"approved"`
			Suspended bool   `json:"suspended"`
			CreatedAt string `json:"created_at"`
		}
		if err := rows.Scan(&user.ID, &user.Email, &user.Role, &user.Approved, &user.Suspended, &user.CreatedAt); err != nil {
			log.Printf("Error processing user data: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  "error",
				"message": "Error processing user data",
			})
			return
		}
		users = append(users, user)
	}

	if len(users) == 0 && userID != "" {
		log.Printf("User not found: %s", userID)
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "User not found",
		})
		return
	}

	log.Printf("Retrieved %d users", len(users))
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   users,
	})
}

// JobsApprove handles the approval of a job by ID
func JobApprove(c *gin.Context) {
	jobID := c.Param("job-id")
	log.Printf("Attempting to approve job with ID: %s", jobID)

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
	defer db.Close()

	var isApproved bool
	query := "SELECT approved FROM jobs WHERE job_id = ?"
	row := db.QueryRow(query, jobID)

	err = row.Scan(&isApproved)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Job not found: %s", jobID)
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found"})
			return
		}
		log.Printf("Database query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database query error"})
		return
	}

	if isApproved {
		log.Printf("Job %s is already approved", jobID)
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Job is already approved",
		})
		return
	}

	updateQuery := "UPDATE jobs SET approved = ? WHERE job_id = ?"
	_, err = db.Exec(updateQuery, true, jobID)
	if err != nil {
		log.Printf("Error updating job approval status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error updating job approval status",
		})
		return
	}

	log.Printf("Job %s approved successfully", jobID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Job approved successfully",
	})
}

// JobsDelete handles the deletion of a job by ID
func JobDelete(c *gin.Context) {
	jobID := c.Param("job-id")
	log.Printf("Attempting to delete job with ID: %s", jobID)

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
	defer db.Close()

	// Check if job exists
	var jobExists bool
	query := "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id = ?)"
	err = db.QueryRow(query, jobID).Scan(&jobExists)
	if err != nil {
		log.Printf("Database query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	if !jobExists {
		log.Printf("Job not found: %s", jobID)
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Job not found",
		})
		return
	}

	deleteQuery := "DELETE FROM jobs WHERE job_id = ?"
	_, err = db.Exec(deleteQuery, jobID)
	if err != nil {
		log.Printf("Error deleting job: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error deleting job",
		})
		return
	}

	log.Printf("Job %s deleted successfully", jobID)
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Job deleted successfully",
	})
}

// JobsViews retrieves all jobs or a specific job by ID from the database and returns them as JSON
func JobViews(c *gin.Context) {
	jobID := c.Param("job-id")
	log.Printf("Retrieving jobs. JobID: %s", jobID)

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
	defer db.Close()

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

	// Filters
	jobType := c.Query("job_type")             // Filter by job type
	jobCategory := c.Query("job_category")     // Filter by job category
	minSalary := c.Query("min_salary")         // Filter by minimum salary
	maxSalary := c.Query("max_salary")         // Filter by maximum salary
	minExperience := c.Query("min_experience") // Filter by minimum experience
	maxExperience := c.Query("max_experience") // Filter by maximum experience
	location := c.Query("location")            // Filter by location
	approvedFilter := c.Query("approved")      // Filter by approval status
	createdAfter := c.Query("created_after")   // Filter by jobs created after a certain date
	createdBefore := c.Query("created_before") // Filter by jobs created before a certain date

	var query string
	var args []interface{}

	if jobID == "" {
		query = "SELECT * FROM jobs WHERE 1=1" // Base query

		// Add filters to the query
		if jobType != "" {
			query += " AND job_type = ?"
			args = append(args, jobType)
		}
		if jobCategory != "" {
			query += " AND job_category = ?"
			args = append(args, jobCategory)
		}
		if minSalary != "" {
			query += " AND min_salary >= ?"
			args = append(args, minSalary)
		}
		if maxSalary != "" {
			query += " AND max_salary <= ?"
			args = append(args, maxSalary)
		}
		if minExperience != "" {
			query += " AND min_experience >= ?"
			args = append(args, minExperience)
		}
		if maxExperience != "" {
			query += " AND max_experience <= ?"
			args = append(args, maxExperience)
		}
		if location != "" {
			query += " AND location = ?"
			args = append(args, location)
		}
		if approvedFilter != "" {
			query += " AND approved = ?"
			if approvedFilter == "true" {
				args = append(args, true)
			} else {
				args = append(args, false)
			}
		}
		if createdAfter != "" {
			query += " AND created_at >= ?"
			args = append(args, createdAfter)
		}
		if createdBefore != "" {
			query += " AND created_at <= ?"
			args = append(args, createdBefore)
		}

		// Execute the query
		rows, err := db.Query(query, args...)
		if err != nil {
			log.Printf("Query execution error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Query execution error"})
			return
		}
		defer rows.Close()

		var jobs []Job

		for rows.Next() {
			var job Job
			if err := rows.Scan(&job.ID, &job.Title, &job.EmployerID, &job.JobCategory, &job.JobType, &job.MinSalary, &job.MaxSalary, &job.MinExperience, &job.MaxExperience, &job.JobResponsibility, &job.Qualification, &job.Benefits, &job.JobDescription, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy, &job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel); err != nil {
				log.Printf("Row scan error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
				return
			}
			jobs = append(jobs, job)
		}

		log.Printf("Retrieved %d jobs", len(jobs))
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   jobs,
		})

	} else {
		// If a specific job ID is provided, retrieve the job by ID
		query := "SELECT * FROM jobs WHERE job_id = ?"
		row := db.QueryRow(query, jobID)

		var job Job
		if err := row.Scan(&job.ID, &job.Title, &job.EmployerID, &job.JobCategory, &job.JobType, &job.MinSalary, &job.MaxSalary, &job.MinExperience, &job.MaxExperience, &job.JobResponsibility, &job.Qualification, &job.Benefits, &job.JobDescription, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy, &job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel); err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Job not found: %s", jobID)
				c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found"})
			} else {
				log.Printf("Row scan error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Row scan error"})
			}
			return
		}

		log.Printf("Retrieved job with ID: %s", jobID)
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   job,
		})
	}
}
