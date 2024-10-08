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

// AuthMiddleware checks for admin role
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
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// UserApprove handles the approval of a user by ID
func UserApprove(c *gin.Context) {
	userID := c.Param("user-id")

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

	// Check if user exists and get their approval status
	var approved bool
	query := "SELECT approved FROM users WHERE id = ?"
	err = db.QueryRow(query, userID).Scan(&approved)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{
				"status":  "error",
				"message": "User not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	// Check if the user is already approved
	if approved {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "User is already approved",
		})
		return
	}

	// Perform approval logic - update the approved status
	updateQuery := "UPDATE users SET approved = ? WHERE id = ?"
	_, err = db.Exec(updateQuery, true, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error updating user approval status",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User approved successfully",
	})
}

// UserDelete handles the deletion of a user by ID
func UserDelete(c *gin.Context) {
	userID := c.Param("user-id")

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

	// Check if user exists
	var userExists bool
	query := "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)"
	err = db.QueryRow(query, userID).Scan(&userExists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}

	if !userExists {
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "User not found",
		})
		return
	}

	// Perform deletion logic
	deleteQuery := "DELETE FROM users WHERE id = ?"
	_, err = db.Exec(deleteQuery, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Error deleting user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "User deleted successfully",
	})
}

// UserViews retrieves all users or a specific user by ID
func UserViews(c *gin.Context) {
	role := c.Param("role")
	userID := c.Param("user-id")

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

	// Prepare the query based on role and userID
	var query string
	var args []interface{}

	if userID == "" {
		if role == "all" {
			query = "SELECT id, email, role, approved, created_at FROM users WHERE role != 'admin'"
		} else {
			query = "SELECT id, email, role, approved, created_at FROM users WHERE role = ? AND role != 'admin'"
			args = append(args, role)
		}
	} else {
		if role == "all" {
			query = "SELECT id, email, role, approved, created_at FROM users WHERE id = ? AND role != 'admin'"
			args = append(args, userID)
		} else {
			query = "SELECT id, email, role, approved, created_at FROM users WHERE role = ? AND id = ? AND role != 'admin'"
			args = append(args, role, userID)
		}
	}

	// Execute the query
	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Database query error",
		})
		return
	}
	defer rows.Close()

	// Process the results
	var users []struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		Approved  bool   `json:"approved"`
		CreatedAt string `json:"created_at"`
	}

	for rows.Next() {
		var user struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			Approved  bool   `json:"approved"`
			CreatedAt string `json:"created_at"`
		}
		if err := rows.Scan(&user.ID, &user.Email, &user.Role, &user.Approved, &user.CreatedAt); err != nil {
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
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   users,
	})
}

// Similarly refactor the `JobsApprove`, `JobsDelete`, and `JobsViews` handlers using the centralized database connection and error handling patterns shown above.

// JobsApprove handles the approval of a job by ID
func JobsApprove(c *gin.Context) {
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

	var approved bool
	query := "SELECT approved FROM jobs WHERE job_id = ?"
	row := db.QueryRow(query, jobID)

	err = row.Scan(&approved)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found"})
			return
		}
		log.Fatal(err)
	}

	if approved {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Job is already approved",
		})
		return
	}

	updateQuery := "UPDATE jobs SET approved = ? WHERE job_id = ?"
	_, err = db.Exec(updateQuery, true, jobID)
	if err != nil {
		log.Fatal(err)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Job approved successfully",
	})
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

	var jobExists bool
	query := "SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id = ?)"
	row := db.QueryRow(query, jobID)

	err = row.Scan(&jobExists)
	if err != nil {
		log.Fatal(err)
	}

	if !jobExists {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Job not found"})
		return
	}

	deleteQuery := "DELETE FROM jobs WHERE job_id = ?"
	_, err = db.Exec(deleteQuery, jobID)
	if err != nil {
		log.Fatal(err)
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Job deleted successfully"})
}

// UserViews retrieves all jobs or a specific job by ID from the database and returns them as JSON
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

	type Job struct {
		ID                  string  `json:"job_id"`               // รหัสงาน
		Title               string  `json:"title"`                // ชื่องาน
		Employer_ID         string  `json:"employer_id"`          // รหัสนายจ้าง
		Job_Category        string  `json:"job_category"`         // หมวดหมู่งาน
		Job_Type            string  `json:"job_type"`             // ประเภทงาน (งานประจำ, งานสัญญาจ้าง)
		Min_Salary          float64 `json:"min_salary"`           // เงินเดือนขั้นต่ำ
		Max_Salary          float64 `json:"max_salary"`           // เงินเดือนสูงสุด
		Min_Experience      int     `json:"min_experience"`       // ประสบการณ์ขั้นต่ำ (ปี)
		Max_Experience      int     `json:"max_experience"`       // ประสบการณ์สูงสุด (ปี)
		Job_Responsibility  string  `json:"job_responsibility"`   // ความรับผิดชอบของงาน
		Qualification       string  `json:"qualification"`        // คุณสมบัติที่ต้องการ
		Benefits            string  `json:"benefits"`             // สวัสดิการ
		Job_Description     string  `json:"job_description"`      // รายละเอียดงาน
		Approved            bool    `json:"approved"`             // สถานะการอนุมัติ
		CreatedAt           string  `json:"created_at"`           // วันเวลาที่สร้าง
		Location            string  `json:"location"`             // สถานที่ทำงาน
		PostedBy            string  `json:"posted_by"`            // ผู้โพสต์งาน
		ApplicationDeadline string  `json:"application_deadline"` // วันหมดเขตการสมัคร
		JobStatus           string  `json:"job_status"`           // สถานะงาน (เปิดรับสมัคร, ปิดรับสมัคร)
		SkillsRequired      string  `json:"skills_required"`      // ทักษะที่ต้องการ
		JobLevel            string  `json:"job_level"`            // ระดับงาน (Junior, Mid-level, Senior)
	}

	if jobID == "" {
		query := "SELECT * FROM jobs"
		rows, err := db.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Query execution error"})
			return
		}
		defer rows.Close()

		var jobs []Job // Initialize an empty slice of Job

		for rows.Next() {
			var job Job
			if err := rows.Scan(&job.ID, &job.Title, &job.Employer_ID, &job.Job_Category, &job.Job_Type, &job.Min_Salary, &job.Max_Salary, &job.Min_Experience, &job.Max_Experience, &job.Job_Responsibility, &job.Qualification, &job.Benefits, &job.Job_Description, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy, &job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel); err != nil {
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
		query := "SELECT * FROM jobs WHERE job_id = ?"
		row := db.QueryRow(query, jobID)

		var job Job
		if err := row.Scan(&job.ID, &job.Title, &job.Employer_ID, &job.Job_Category, &job.Job_Type, &job.Min_Salary, &job.Max_Salary, &job.Min_Experience, &job.Max_Experience, &job.Job_Responsibility, &job.Qualification, &job.Benefits, &job.Job_Description, &job.Approved, &job.CreatedAt, &job.Location, &job.PostedBy, &job.ApplicationDeadline, &job.JobStatus, &job.SkillsRequired, &job.JobLevel); err != nil {
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
