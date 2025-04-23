package data

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// DB represents a database connection
type DB struct {
	db *sql.DB
}

// NewDB creates a new database connection
func NewDB(dbPath string) (*DB, error) {
	fmt.Printf("Opening database at %s\n", dbPath)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		fmt.Printf("Failed to ping database: %v\n", err)
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	fmt.Println("Successfully connected to database")

	// Create tables if they don't exist
	fmt.Println("Creating tables...")
	if err := createTables(db); err != nil {
		fmt.Printf("Failed to create tables: %v\n", err)
		db.Close()
		return nil, err
	}

	fmt.Println("Database initialized successfully")
	return &DB{db: db}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.db.Close()
}

// createTables creates the necessary tables if they don't exist
func createTables(db *sql.DB) error {
	fmt.Println("Starting table creation...")

	// Create reports table
	fmt.Println("Creating reports table...")
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			cluster TEXT NOT NULL,
			namespace TEXT NOT NULL,
			name TEXT NOT NULL,
			status TEXT,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(type, cluster, namespace, name)
		)
	`)
	if err != nil {
		fmt.Printf("Failed to create reports table: %v\n", err)
		return fmt.Errorf("failed to create reports table: %w", err)
	}
	fmt.Println("Reports table created successfully")

	// Create clusters table
	fmt.Println("Creating clusters table...")
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS clusters (
			name TEXT PRIMARY KEY,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		fmt.Printf("Failed to create clusters table: %v\n", err)
		return fmt.Errorf("failed to create clusters table: %w", err)
	}
	fmt.Println("Clusters table created successfully")

	// Create namespaces table
	fmt.Println("Creating namespaces table...")
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS namespaces (
			cluster TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (cluster, name)
		)
	`)
	if err != nil {
		fmt.Printf("Failed to create namespaces table: %v\n", err)
		return fmt.Errorf("failed to create namespaces table: %w", err)
	}
	fmt.Println("Namespaces table created successfully")

	fmt.Println("All tables created successfully")
	return nil
}
