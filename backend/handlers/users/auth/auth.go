package auth

import (
	"fresh-grad-jobs/services"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// SignInHandler handles the user login and generates a token
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

	// Fetch the user information from the database
	var storedPasswordHash string
	query := "SELECT password_hash FROM users WHERE email = ?"
	err = db.QueryRow(query, loginRequest.Email).Scan(&storedPasswordHash)
	if err != nil {
		log.Printf("User not found or database error for email: %s, error: %v", loginRequest.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid email or password"})
		return
	}

	// Compare the stored hashed password with the provided password
	if err := bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(loginRequest.Password)); err != nil {
		log.Printf("Invalid password for email: %s", loginRequest.Email)
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Invalid email or password"})
		return
	}

	// Generate the JWT token
	token, err := services.GenerateJWT(loginRequest.Email, loginRequest.Password, db)
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
