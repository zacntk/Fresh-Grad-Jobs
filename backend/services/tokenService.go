package services

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

// Initialize environment variables once (suggested to be done in main function)
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

// GenerateJWT generates a JWT for the given user with a specific role
func GenerateJWT(email, password string, db *sql.DB) (string, error) {
	// Retrieve secret key and application name from the environment
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Fatal("Secret key not found in environment variables")
	}
	iss := os.Getenv("APP_NAME")

	// Query the database for user role (example with hardcoded email and password)
	query := "SELECT role FROM users WHERE email = ? AND password = ?"
	var role string
	err := db.QueryRow(query, email, password).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("user not found or invalid credentials")
		}
		return "", fmt.Errorf("database query error: %v", err)
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"role": role,
		"exp":  time.Now().Add(time.Hour * 1).Unix(), // Set expiration time to 1 hour
		"iss":  iss,
	}

	// Create a new JWT token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("error signing the token: %v", err)
	}

	return tokenString, nil
}

// ValidateJWT validates a JWT token and returns the user's role if valid
func ValidateJWT(tokenString string) (string, error) {
	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Retrieve secret key from environment variables
		secretKey := os.Getenv("SECRET_KEY")
		if secretKey == "" {
			log.Fatal("Secret key not found in environment variables")
		}

		return []byte(secretKey), nil
	})

	if err != nil {
		return "", err
	}

	// Check token claims and validity
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Optional: Check the expiration time
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return "", fmt.Errorf("token has expired")
			}
		}
		// Return the user role
		if role, ok := claims["role"].(string); ok {
			return role, nil
		}
		return "", fmt.Errorf("role not found in token claims")
	}
	return "", fmt.Errorf("invalid token")
}
