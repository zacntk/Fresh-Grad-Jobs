package services

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql" // Import MySQL driver
	"github.com/joho/godotenv"
)

// connectDB initializes a connection to the database using DSN from .env file
func ConnectDB() (*sql.DB, error) {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading .env file: %v", err)
	}

	// Get DSN from environment variables
	dsn := os.Getenv("DSN")
	if dsn == "" {
		return nil, fmt.Errorf("DSN environment variable not set")
	}

	// Open a connection to the database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %v", err)
	}

	// Check if the connection is established
	if err := db.Ping(); err != nil {
		db.Close() // Close the connection if ping fails
		return nil, fmt.Errorf("error pinging database: %v", err)
	}

	log.Printf("Successfully connected to the database!")
	return db, nil
}
