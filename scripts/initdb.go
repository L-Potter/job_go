package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	_ "github.com/mattn/go-sqlite3"
)

const (
	HMAC_SECRET = "your-hmac-secret-key"
)

func main() {
	// Database file path
	dbPath := filepath.Join("..", "database.db")

	// Check if database file already exists
	if _, err := os.Stat(dbPath); err == nil {
		fmt.Printf("⚠️  Database file already exists: %s\n", dbPath)
		fmt.Println("   If you need to reinitialize, please delete this file first")
		os.Exit(0)
	}

	fmt.Println("📦 Initializing database...")

	// Create database connection
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("❌ Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		log.Fatalf("❌ Failed to enable foreign keys: %v", err)
	}

	fmt.Println("✅ Connected to database")

	// Initialize database
	err = initializeDatabase(db)
	if err != nil {
		log.Fatalf("❌ Database initialization failed: %v", err)
	}

	// Set hidden attribute on Windows
	if runtime.GOOS == "windows" {
		err = setHiddenAttribute(dbPath)
		if err != nil {
			fmt.Printf("⚠️  Failed to set hidden attribute: %v\n", err)
		} else {
			fmt.Println("✅ Database file set as hidden on Windows")
		}
	}

	fmt.Println("\n🎉 Database initialization completed!")
	fmt.Printf("📁 Database file location: %s\n", dbPath)
}

func initializeDatabase(db *sql.DB) error {
	// Create tables
	err := createTables(db)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Insert default data
	err = insertDefaultData(db)
	if err != nil {
		return fmt.Errorf("failed to insert default data: %w", err)
	}

	return nil
}

func createTables(db *sql.DB) error {
	// Create leave_types table
	leaveTypesTable := `
		CREATE TABLE leave_types (
			leave_id       INTEGER PRIMARY KEY AUTOINCREMENT,
			name           TEXT NOT NULL UNIQUE,
			is_not_workday INTEGER DEFAULT 0,
			color          TEXT DEFAULT '#ff9800',
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`

	_, err := db.Exec(leaveTypesTable)
	if err != nil {
		return fmt.Errorf("failed to create leave_types table: %w", err)
	}
	fmt.Println("✅ Created table: leave_types")

	// Create calendar_tags table
	calendarTagsTable := `
		CREATE TABLE calendar_tags (
			date        DATE PRIMARY KEY,
			is_holiday  BOOLEAN DEFAULT 0,
			shift_type  TEXT CHECK(shift_type IN ('A', 'B')),
			updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			comment     TEXT
		)`

	_, err = db.Exec(calendarTagsTable)
	if err != nil {
		return fmt.Errorf("failed to create calendar_tags table: %w", err)
	}
	fmt.Println("✅ Created table: calendar_tags")

	// Create users table
	usersTable := `
		CREATE TABLE users (
			user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
			name          TEXT NOT NULL,
			employee_id   TEXT NOT NULL UNIQUE,
			shift_type    TEXT CHECK(shift_type IN ('A', 'B')),
			site          TEXT CHECK(site IN ('P1', 'P2', 'P3', 'P4')),
			password_hash TEXT NOT NULL,
			role          TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			day_night     TEXT CHECK(day_night IN ('D', 'N'))
		)`

	_, err = db.Exec(usersTable)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	fmt.Println("✅ Created table: users")

	return nil
}

func insertDefaultData(db *sql.DB) error {
	// Insert admin user
	err := insertAdminUser(db)
	if err != nil {
		return fmt.Errorf("failed to insert admin user: %w", err)
	}
	fmt.Println("✅ Created admin user: admin (password: 663955)")

	// Insert default leave types
	err = insertDefaultLeaveTypes(db)
	if err != nil {
		return fmt.Errorf("failed to insert default leave types: %w", err)
	}
	fmt.Println("✅ Inserted default leave types data")

	return nil
}

func insertAdminUser(db *sql.DB) error {
	passwordHash := hashPassword("admin")

	_, err := db.Exec(`
		INSERT INTO users (name, employee_id, password_hash, shift_type, site, role, day_night)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"Administrator", "admin", passwordHash, "B", "P1", "admin", "D")

	return err
}

func insertDefaultLeaveTypes(db *sql.DB) error {
	defaultLeaveTypes := [][]interface{}{
		{"事假", 0, "#ff9800"},
		{"病假", 0, "#f44336"},
		{"特休", 0, "#2196f3"},
		{"加班", 1, "#9c27b0"},
	}

	for _, leaveType := range defaultLeaveTypes {
		_, err := db.Exec(`
			INSERT INTO leave_types (name, is_not_workday, color)
			VALUES (?, ?, ?)`,
			leaveType[0], leaveType[1], leaveType[2])

		if err != nil {
			return err
		}
	}

	return nil
}

func hashPassword(password string) string {
	h := hmac.New(sha256.New, []byte(HMAC_SECRET))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

func setHiddenAttribute(filePath string) error {
	// Use attrib command to set hidden attribute on Windows
	cmd := exec.Command("attrib", "+h", filePath)
	return cmd.Run()
}
