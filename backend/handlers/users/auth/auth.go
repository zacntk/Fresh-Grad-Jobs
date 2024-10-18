package auth

import (
	"database/sql"
	"fresh-grad-jobs/services"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// SignInHandler handles the user login and generates a JWT token
func SignInHandler(c *gin.Context) {
	// Declare a struct to bind the JSON request
	var loginRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	// Bind the JSON body to the struct
	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Invalid request format"})
		return
	}

	// Log the login attempt (for debugging/audit)
	log.Printf("Login attempt for email: %s", loginRequest.Email)

	// Connect to the database
	db, err := services.ConnectDB()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database connection error"})
		return
	}
	defer db.Close()

	// Combine fetching user information and suspension status into a single query
	var storedPasswordHash string
	var userID int
	var isSuspended bool
	query := "SELECT user_id, password_hash, suspended FROM users WHERE email = ?"
	err = db.QueryRow(query, loginRequest.Email).Scan(&userID, &storedPasswordHash, &isSuspended)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found for email: %s", loginRequest.Email)
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid email or password"})
			return
		}
		log.Printf("Database query error for email: %s, error: %v", loginRequest.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Database query error"})
		return
	}

	// Compare the stored hashed password with the provided password
	if err := bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(loginRequest.Password)); err != nil {
		log.Printf("Invalid password for email: %s", loginRequest.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid email or password"})
		return
	}

	// Check if the user is suspended
	if isSuspended {
		log.Printf("User with ID %d is suspended", userID)
		c.JSON(http.StatusForbidden, gin.H{
			"status":  "error",
			"message": "Your account is suspended",
		})
		return
	}

	// Generate the JWT token
	token, err := services.GenerateJWT(userID, db)
	if err != nil {
		log.Printf("Error generating JWT for email: %s, error: %v", loginRequest.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Token generation error"})
		return
	}

	// Log the successful login
	log.Printf("User successfully logged in: %s", loginRequest.Email)

	// Return the generated token
	c.JSON(http.StatusOK, gin.H{"status": "success", "token": token})
}
