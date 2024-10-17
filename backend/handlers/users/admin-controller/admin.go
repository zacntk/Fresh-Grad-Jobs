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

// TODO: Suspend user ❌
// ระงับการใช้งานของผู้ใช้ชั่วคราวในกรณีที่มีการละเมิดกฎ

// TODO: Search/filter users/jobs ❌
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
	var approved bool
	query := "SELECT approved FROM users WHERE user_id = ?"
	err = db.QueryRow(query, userID).Scan(&approved)
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
	if approved {
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

// UserViews retrieves all users or a specific user by ID
func UserViews(c *gin.Context) {
	role := c.Param("role")
	userID := c.Param("user-id")
	log.Printf("Retrieving users. Role: %s, UserID: %s", role, userID)

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

	// Prepare the query based on role and userID
	var query string
	var args []interface{}

	if userID == "" {
		if role == "all" {
			query = "SELECT user_id, email, role, approved, created_at FROM users WHERE role != 'admin'"
		} else {
			query = "SELECT user_id, email, role, approved, created_at FROM users WHERE role = ? AND role != 'admin'"
			args = append(args, role)
		}
	} else {
		if role == "all" {
			query = "SELECT user_id, email, role, approved, created_at FROM users WHERE user_id = ? AND role != 'admin'"
			args = append(args, userID)
		} else {
			query = "SELECT user_id, email, role, approved, created_at FROM users WHERE role = ? AND user_id = ? AND role != 'admin'"
			args = append(args, role, userID)
		}
	}

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

	// Process the results
	var users []struct {
		ID        string `json:"user_id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		Approved  bool   `json:"approved"`
		CreatedAt string `json:"created_at"`
	}

	for rows.Next() {
		var user struct {
			ID        string `json:"user_id"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			Approved  bool   `json:"approved"`
			CreatedAt string `json:"created_at"`
		}
		if err := rows.Scan(&user.ID, &user.Email, &user.Role, &user.Approved, &user.CreatedAt); err != nil {
			log.Printf("Error processing user data: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  "error",
				"message": "Error processing user data",
			})
			return
		}
		users = append(users, user)
	}

	// Return the results as JSON
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
func JobsApprove(c *gin.Context) {
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

	var approved bool
	query := "SELECT approved FROM jobs WHERE job_id = ?"
	row := db.QueryRow(query, jobID)

	err = row.Scan(&approved)
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

	if approved {
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
func JobsDelete(c *gin.Context) {
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
func JobsViews(c *gin.Context) {
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

	if jobID == "" {
		query := "SELECT * FROM jobs"
		rows, err := db.Query(query)
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
