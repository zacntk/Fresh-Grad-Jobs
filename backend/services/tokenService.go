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

// Initialize environment variables (suggested to be done in the main function)
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file. Ensure environment variables are set.")
	}
}

// GenerateJWT generates a JWT for the given user after verifying credentials
func GenerateJWT(userID int, db *sql.DB) (string, error) {
	// Retrieve secret key and application name from the environment
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		return "", fmt.Errorf("secret key not found in environment variables")
	}

	iss := os.Getenv("APP_NAME")
	if iss == "" {
		return "", fmt.Errorf("app name not found in environment variables")
	}

	// Query the database for the user's role
	query := "SELECT role FROM users WHERE user_id = ?"
	var role string
	err := db.QueryRow(query, userID).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("user not found")
		}
		return "", fmt.Errorf("database query error: %v", err)
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"id":   userID,
		"role": role,
		"exp":  time.Now().Add(time.Hour * 1).Unix(), // Set expiration time
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

// JWTClaims holds the claims for the JWT token
type JWTClaims struct {
	ID   int    `json:"id"`
	Role string `json:"role"`
}

// ValidateJWT validates a JWT token and returns the user ID and role
func ValidateJWT(tokenString string) (*JWTClaims, error) {
	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Retrieve secret key from environment variables
		secretKey := os.Getenv("SECRET_KEY")
		if secretKey == "" {
			return nil, fmt.Errorf("secret key not found in environment variables")
		}

		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	// Check token claims and validity
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Optional: Check the expiration time
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return nil, fmt.Errorf("token has expired")
			}
		}

		// Create an instance of JWTClaims to hold the extracted claims
		jwtClaims := &JWTClaims{}

		// Extracting ID and role from claims
		if id, ok := claims["id"].(float64); ok {
			jwtClaims.ID = int(id) // Convert float64 to int
		} else {
			return nil, fmt.Errorf("id not found in token claims")
		}

		if role, ok := claims["role"].(string); ok {
			jwtClaims.Role = role
		} else {
			return nil, fmt.Errorf("role not found in token claims")
		}

		return jwtClaims, nil
	}
	return nil, fmt.Errorf("invalid token")
}
