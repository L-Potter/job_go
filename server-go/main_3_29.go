package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"server-go/ui"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

//go:embed build/*
var staticFS embed.FS

const (
	PORT         = 3001
	HMAC_SECRET  = "your-hmac-secret-key"
	DB_PATH      = "../database.db"
	FRONTEND_URL = "http://localhost:5175"
)

var mainDB *resilientDB

type resilientDB struct {
	mu         sync.RWMutex
	db         *sql.DB
	dbPath     string
	maxRetries int
	retryDelay time.Duration
}

type resilientRow struct {
	parent *resilientDB
	query  string
	args   []interface{}
}

type Date struct {
	time.Time
}

func (d Date) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.Format("2006-01-02") + `"`), nil
}

func (d *Date) Scan(value interface{}) error {
	switch v := value.(type) {
	case time.Time:
		d.Time = v
		return nil
	case string:
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return err
		}
		d.Time = t
		return nil
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}
}

// Timestamp type for full datetime formatting
type Timestamp struct {
	time.Time
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.Format("2006-01-02 15:04:05") + `"`), nil
}

func (t *Timestamp) Scan(value interface{}) error {
	switch v := value.(type) {
	case time.Time:
		t.Time = v
		return nil
	case string:
		// Try parsing as full datetime first, then as date-only
		if parsed, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
			t.Time = parsed
			return nil
		}
		// Fallback to date parsing
		if parsed, err := time.Parse("2006-01-02", v); err == nil {
			t.Time = parsed
			return nil
		}
		return fmt.Errorf("unsupported timestamp format: %s", v)
	default:
		return fmt.Errorf("unsupported type for Timestamp: %T", value)
	}
}

type User struct {
	UserID       int        `json:"user_id"`
	Name         string     `json:"name"`
	EmployeeID   string     `json:"employee_id"`
	ShiftType    *string    `json:"shift_type"`
	Site         *string    `json:"site"`
	DayNight     *string    `json:"day_night"`
	Role         string     `json:"role"`
	Group        string     `json:"group"`
	PasswordHash string     `json:"-"`
	CreatedAt    *Timestamp `json:"created_at"`
}

type CalendarTag struct {
	Date      Date    `json:"date"`
	IsHoliday int     `json:"is_holiday"`
	ShiftType *string `json:"shift_type"`
	Comment   *string `json:"comment"`
	UpdatedAt string  `json:"updated_at"`
}

type ShiftAssignment struct {
	EmployeeID string     `json:"employee_id"`
	Date       Date       `json:"date"`
	ShiftType  string     `json:"shift_type"`
	Comment    string     `json:"comment"`
	CreatedAt  *Timestamp `json:"created_at"`
	UpdatedAt  *Timestamp `json:"updated_at"`
}

type LeaveType struct {
	LeaveID      int        `json:"leave_id"`
	Name         string     `json:"name"`
	IsNotWorkday int        `json:"is_not_workday"`
	Color        string     `json:"color"`
	CreatedAt    *Timestamp `json:"created_at"`
}

type LogEntry struct {
	LogID      int        `json:"log_id"`
	User       string     `json:"user"`
	Action     string     `json:"action"`
	TableName  string     `json:"table_name"`
	RecordID   string     `json:"record_id"`
	Details    string     `json:"details"`
	CreatedAt  *Timestamp `json:"created_at"`
}

type LeaveRecord struct {
	UserID      int        `json:"user_id"`
	LeaveTypeID int        `json:"leave_type_id"`
	Date        string     `json:"date"`
	TotalHours  float32    `json:"total_hours"`
	CreatedAt   *Timestamp `json:"created_at"`
}

func main() {
	// Initialize main database
	var err error
	mainDB, err = newResilientDB(DB_PATH)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer mainDB.Close()

	// Setup routes
	router := gin.Default()

	addRoutes(router)

	ui.AddRoutes(router, staticFS)

	log.Printf("🚀 API server running on http://localhost:%d", PORT)
	router.Run(fmt.Sprintf(":%d", PORT))
}

func newResilientDB(dbPath string) (*resilientDB, error) {
	db, err := initDatabase(dbPath)
	if err != nil {
		return nil, err
	}

	return &resilientDB{
		db:         db,
		dbPath:     dbPath,
		maxRetries: 2,
		retryDelay: 300 * time.Millisecond,
	}, nil
}

func (r *resilientDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	var lastErr error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		db, err := r.currentDB()
		if err != nil {
			return nil, err
		}

		rows, err := db.Query(query, args...)
		if err == nil {
			return rows, nil
		}
		if !isSQLiteLockedOrBusyErr(err) {
			return nil, err
		}

		lastErr = err
		log.Printf("mainDB.Query locked/busy, reconnecting (%d/%d): %v", attempt+1, r.maxRetries+1, err)
		if reconnectErr := r.reconnect(); reconnectErr != nil {
			return nil, fmt.Errorf("%w; reconnect failed: %v", err, reconnectErr)
		}
		if attempt < r.maxRetries {
			time.Sleep(r.retryDelay)
		}
	}

	return nil, lastErr
}

func (r *resilientDB) QueryRow(query string, args ...interface{}) *resilientRow {
	return &resilientRow{
		parent: r,
		query:  query,
		args:   append([]interface{}(nil), args...),
	}
}

func (rr *resilientRow) Scan(dest ...interface{}) error {
	var lastErr error

	for attempt := 0; attempt <= rr.parent.maxRetries; attempt++ {
		db, err := rr.parent.currentDB()
		if err != nil {
			return err
		}

		err = db.QueryRow(rr.query, rr.args...).Scan(dest...)
		if err == nil || err == sql.ErrNoRows {
			return err
		}
		if !isSQLiteLockedOrBusyErr(err) {
			return err
		}

		lastErr = err
		log.Printf("mainDB.QueryRow locked/busy, reconnecting (%d/%d): %v", attempt+1, rr.parent.maxRetries+1, err)
		if reconnectErr := rr.parent.reconnect(); reconnectErr != nil {
			return fmt.Errorf("%w; reconnect failed: %v", err, reconnectErr)
		}
		if attempt < rr.parent.maxRetries {
			time.Sleep(rr.parent.retryDelay)
		}
	}

	return lastErr
}

func (r *resilientDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	var lastErr error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		db, err := r.currentDB()
		if err != nil {
			return nil, err
		}

		result, err := db.Exec(query, args...)
		if err == nil {
			return result, nil
		}
		if !isSQLiteLockedOrBusyErr(err) {
			return nil, err
		}

		lastErr = err
		log.Printf("mainDB.Exec locked/busy, reconnecting (%d/%d): %v", attempt+1, r.maxRetries+1, err)
		if reconnectErr := r.reconnect(); reconnectErr != nil {
			return nil, fmt.Errorf("%w; reconnect failed: %v", err, reconnectErr)
		}
		if attempt < r.maxRetries {
			time.Sleep(r.retryDelay)
		}
	}

	return nil, lastErr
}

func (r *resilientDB) Begin() (*sql.Tx, error) {
	var lastErr error

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		db, err := r.currentDB()
		if err != nil {
			return nil, err
		}

		tx, err := db.Begin()
		if err == nil {
			return tx, nil
		}
		if !isSQLiteLockedOrBusyErr(err) {
			return nil, err
		}

		lastErr = err
		log.Printf("mainDB.Begin locked/busy, reconnecting (%d/%d): %v", attempt+1, r.maxRetries+1, err)
		if reconnectErr := r.reconnect(); reconnectErr != nil {
			return nil, fmt.Errorf("%w; reconnect failed: %v", err, reconnectErr)
		}
		if attempt < r.maxRetries {
			time.Sleep(r.retryDelay)
		}
	}

	return nil, lastErr
}

func (r *resilientDB) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.db == nil {
		return nil
	}

	err := r.db.Close()
	r.db = nil
	return err
}

func (r *resilientDB) currentDB() (*sql.DB, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.db == nil {
		return nil, fmt.Errorf("database is not initialized")
	}

	return r.db, nil
}

func (r *resilientDB) reconnect() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.db != nil {
		if err := r.db.Close(); err != nil {
			log.Printf("mainDB close before reconnect failed: %v", err)
		}
		r.db = nil
	}

	db, err := initDatabase(r.dbPath)
	if err != nil {
		return err
	}
	r.db = db
	return nil
}

func isSQLiteLockedOrBusyErr(err error) bool {
	if err == nil {
		return false
	}

	lowerErr := strings.ToLower(err.Error())
	return strings.Contains(lowerErr, "locked") || strings.Contains(lowerErr, "busy")
}

func addRoutes(router *gin.Engine) {
	api := router.Group("/api")
	{
		// Auth routes
		api.POST("/login", loginHandler)
		api.POST("/logout", logoutHandler)
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// User routes
		api.GET("/users", getUsersHandler)
		api.POST("/users", createUserHandler)
		api.GET("/users/:id", getUserHandler)
		api.PUT("/users/:id", updateUserHandler)
		api.DELETE("/users/:id", deleteUserHandler)

		// Calendar tags routes
		api.GET("/calendar-tags", getCalendarTagsHandler)
		api.GET("/calendar-tags/:date", getCalendarTagHandler)
		api.PUT("/calendar-tags/:date", setCalendarTagHandler)
		api.DELETE("/calendar-tags/:date", deleteCalendarTagHandler)
		api.POST("/calendar-tags/batch", batchCalendarTagsHandler)

		// Shift assignments routes
		api.GET("/shift-assignments/:employeeId", getShiftAssignmentsHandler)
		api.PUT("/shift-assignments/:employeeId/:date", setShiftAssignmentHandler)
		api.DELETE("/shift-assignments/:employeeId/:date", deleteShiftAssignmentHandler)
		api.POST("/shift-assignments/:employeeId/move", moveShiftAssignmentHandler)

		// Leave types routes
		api.GET("/leave-types", getLeaveTypesHandler)
		api.GET("/leave-types/:id", getLeaveTypeHandler)
		api.POST("/leave-types", createLeaveTypeHandler)
		api.PUT("/leave-types/:id", updateLeaveTypeHandler)
		api.DELETE("/leave-types/:id", deleteLeaveTypeHandler)

		// Admin log routes
		api.GET("/logs", getLogsHandler)
	}
}

func initDatabase(dbPath string) (*sql.DB, error) {
	var db *sql.DB
	var err error
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		db, err = sql.Open("sqlite", dbPath)
		if err != nil {
			if strings.Contains(err.Error(), "locked") || strings.Contains(err.Error(), "lock") {
				log.Printf("Database locked, retrying... (%d/%d)", i+1, maxRetries)
				time.Sleep(time.Second)
				continue
			}
			return nil, err
		}
		break
	}

	if err != nil {
		return nil, err
	}

	// SQLite in API servers is more stable with a single writer connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Set busy timeout to 3000ms
	_, err = db.Exec("PRAGMA busy_timeout = 3000")
	if err != nil {
		return nil, err
	}

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return nil, err
	}

	// Create tables if they don't exist
	err = createTables(db)
	if err != nil {
		return nil, err
	}

	log.Println("✅ Connected to db")
	return db, nil
}

func createTables(db *sql.DB) error {
	// Users table
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name           TEXT NOT NULL,
		employee_id    TEXT UNIQUE NOT NULL,
		password_hash  TEXT NOT NULL,
		shift_type     TEXT,
		site           TEXT,
		day_night      TEXT,
		role           TEXT DEFAULT 'user',
		"group"        TEXT NOT NULL DEFAULT '',
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// Calendar tags table
	calendarTagsTable := `
	CREATE TABLE IF NOT EXISTS calendar_tags (
		date        DATE PRIMARY KEY,
		is_holiday  BOOLEAN DEFAULT 0,
		shift_type  TEXT CHECK(shift_type IN ('A', 'B')),
		comment     TEXT,
		updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// Leave types table
	leaveTypesTable := `
	CREATE TABLE IF NOT EXISTS leave_types (
		leave_id       INTEGER PRIMARY KEY AUTOINCREMENT,
		name           TEXT UNIQUE NOT NULL,
		is_not_workday INTEGER DEFAULT 0,
		color          TEXT DEFAULT '#ff9800',
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// Admin log table
	adminLogTable := `
	CREATE TABLE IF NOT EXISTS admin_log (
		log_id         INTEGER PRIMARY KEY AUTOINCREMENT,
		action         TEXT NOT NULL,
		table_name     TEXT NOT NULL,
		record_id      TEXT NOT NULL,
		details        TEXT,
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	tables := []string{usersTable, calendarTagsTable, leaveTypesTable, adminLogTable}
	for _, table := range tables {
		_, err := db.Exec(table)
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

// ==================== Authentication Handlers ====================

func loginHandler(c *gin.Context) {
	var req struct {
		EmployeeID string `json:"employee_id"`
		Password   string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.EmployeeID == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工號和密碼為必填項"})
		return
	}

	var user User
	var shiftType, site, dayNight sql.NullString
	var createdAt sql.NullTime

	err := mainDB.QueryRow(`
		SELECT user_id, name, employee_id, shift_type, site, day_night, role, "group", created_at
		FROM users WHERE employee_id = ?
	`, req.EmployeeID).Scan(
		&user.UserID, &user.Name, &user.EmployeeID,
		&shiftType, &site, &dayNight, &user.Role, &user.Group, &createdAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "工號或密碼錯誤"})
		return
	} else if err != nil {
		log.Printf("Login query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登入失敗"})
		return
	}

	// Check password
	var passwordHash string
	err = mainDB.QueryRow("SELECT password_hash FROM users WHERE employee_id = ?", req.EmployeeID).Scan(&passwordHash)
	if err != nil {
		log.Printf("Password query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登入失敗"})
		return
	}

	if hashPassword(req.Password) != passwordHash {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "工號或密碼錯誤"})
		return
	}

	user.ShiftType = nilIfEmpty(shiftType)
	user.Site = nilIfEmpty(site)
	user.DayNight = nilIfEmpty(dayNight)
	user.CreatedAt = nilIfZeroTimestamp(createdAt)

	c.JSON(http.StatusOK, user)
}

func logoutHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
}

func getUsersHandler(c *gin.Context) {
	rows, err := mainDB.Query(`
		SELECT user_id, name, employee_id, shift_type, site, day_night, role, "group", created_at
		FROM users ORDER BY created_at DESC
	`)
	if err != nil {
		log.Printf("Get users error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户列表失败"})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		var shiftType, site, dayNight sql.NullString
		var createdAt sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.Name, &user.EmployeeID,
			&shiftType, &site, &dayNight, &user.Role, &user.Group, &createdAt,
		)
		if err != nil {
			log.Printf("Scan user error: %v", err)
			continue
		}

		user.ShiftType = nilIfEmpty(shiftType)
		user.Site = nilIfEmpty(site)
		user.DayNight = nilIfEmpty(dayNight)
		user.CreatedAt = nilIfZeroTimestamp(createdAt)

		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

func getUserHandler(c *gin.Context) {
	userID := c.Param("id")

	var user User
	var shiftType, site, dayNight sql.NullString
	var createdAt sql.NullTime

	err := mainDB.QueryRow(`
		SELECT user_id, name, employee_id, shift_type, site, day_night, role, "group", created_at
		FROM users WHERE user_id = ?
	`, userID).Scan(
		&user.UserID, &user.Name, &user.EmployeeID,
		&shiftType, &site, &dayNight, &user.Role, &user.Group, &createdAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	} else if err != nil {
		log.Printf("Get user error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户失败"})
		return
	}

	user.ShiftType = nilIfEmpty(shiftType)
	user.Site = nilIfEmpty(site)
	user.DayNight = nilIfEmpty(dayNight)
	user.CreatedAt = nilIfZeroTimestamp(createdAt)

	c.JSON(http.StatusOK, user)
}

func createUserHandler(c *gin.Context) {
	var req struct {
		Name       string  `json:"name"`
		EmployeeID string  `json:"employee_id"`
		Password   string  `json:"password"`
		ShiftType  *string `json:"shift_type"`
		Site       *string `json:"site"`
		DayNight   *string `json:"day_night"`
		Role       string  `json:"role"`
		Group      string  `json:"group"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" || req.EmployeeID == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "姓名、工號和密碼為必填項"})
		return
	}

	// Check if employee_id already exists
	var existingID int
	err := mainDB.QueryRow("SELECT user_id FROM users WHERE employee_id = ?", req.EmployeeID).Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "此工號已存在"})
		return
	} else if err != sql.ErrNoRows {
		log.Printf("Check employee_id error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查工號失败"})
		return
	}

	role := req.Role
	if role == "" {
		role = "user"
	}

	passwordHash := hashPassword(req.Password)

	result, err := mainDB.Exec(`
		INSERT INTO users (name, employee_id, password_hash, shift_type, site, day_night, role, "group")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.EmployeeID, passwordHash, req.ShiftType, req.Site, req.DayNight, role, req.Group)

	if err != nil {
		log.Printf("Create user error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}

	userID, _ := result.LastInsertId()
	logAdminAction("CREATE", "users", req.EmployeeID, fmt.Sprintf("Created user: %s (Role: %s)", req.Name, role))

	// Create user-specific database file
	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", req.EmployeeID))

	userDb, err := sql.Open("sqlite", userDbPath)
	if err != nil {
		log.Printf("Create user DB error: %v", err)
		// Don't return error, user is already created
	} else {
		// Create leave_records table
		_, err = userDb.Exec(`
			CREATE TABLE IF NOT EXISTS leave_records (
				user_id        INTEGER NOT NULL,
				leave_type_id  INTEGER NOT NULL,
				date           DATE NOT NULL,
				total_hours    DECIMAL(4,2) NOT NULL,
				created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			log.Printf("Create leave_records table error: %v", err)
		}

		// Create user_log table
		_, err = userDb.Exec(`
			CREATE TABLE IF NOT EXISTS user_log (
				log_id INTEGER PRIMARY KEY AUTOINCREMENT,
				action TEXT NOT NULL,
				table_name TEXT NOT NULL,
				record_id TEXT NOT NULL,
				details TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			log.Printf("Create user_log table error: %v", err)
		} else {
			log.Printf("✅ User database and tables created: %s.db", req.EmployeeID)
		}
		userDb.Close()
	}

	// Set hidden attribute on Windows
	cmd := exec.Command("attrib", "+h", userDbPath)
	err = cmd.Run()
	if err != nil {
		log.Printf("Failed to set hidden attribute on user DB: %v", err)
	}

	response := map[string]interface{}{
		"user_id":     int(userID),
		"name":        req.Name,
		"employee_id": req.EmployeeID,
		"shift_type":  req.ShiftType,
		"site":        req.Site,
		"day_night":   req.DayNight,
		"role":        role,
		"group":       req.Group,
	}

	c.JSON(http.StatusCreated, response)
}

func updateUserHandler(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Name       string  `json:"name"`
		EmployeeID string  `json:"employee_id"`
		ShiftType  *string `json:"shift_type"`
		Site       *string `json:"site"`
		DayNight   *string `json:"day_night"`
		Role       string  `json:"role"`
		Group      *string `json:"group"`
		Password   string  `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Check if user exists
	var existingID int
	err := mainDB.QueryRow("SELECT user_id FROM users WHERE user_id = ?", userID).Scan(&existingID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	} else if err != nil {
		log.Printf("Check user exists error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查用户失败"})
		return
	}

	// Check employee_id conflict if provided
	if req.EmployeeID != "" {
		var conflictID int
		err := mainDB.QueryRow("SELECT user_id FROM users WHERE employee_id = ? AND user_id != ?", req.EmployeeID, userID).Scan(&conflictID)
		if err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "此工號已被其他用户使用"})
			return
		} else if err != sql.ErrNoRows {
			log.Printf("Check employee_id conflict error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "检查工號冲突失败"})
			return
		}
	}

	// Build update query
	setParts := []string{}
	args := []interface{}{}

	if req.Name != "" {
		setParts = append(setParts, "name = ?")
		args = append(args, req.Name)
	}
	if req.EmployeeID != "" {
		setParts = append(setParts, "employee_id = ?")
		args = append(args, req.EmployeeID)
	}
	if req.Password != "" {
		setParts = append(setParts, "password_hash = ?")
		args = append(args, hashPassword(req.Password))
	}
	if req.ShiftType != nil {
		setParts = append(setParts, "shift_type = ?")
		args = append(args, *req.ShiftType)
	}
	if req.Site != nil {
		setParts = append(setParts, "site = ?")
		args = append(args, *req.Site)
	}
	if req.DayNight != nil {
		setParts = append(setParts, "day_night = ?")
		args = append(args, *req.DayNight)
	}
	if req.Role != "" {
		setParts = append(setParts, "role = ?")
		args = append(args, req.Role)
	}
	if req.Group != nil {
		setParts = append(setParts, "\"group\" = ?")
		args = append(args, *req.Group)
	}

	if len(setParts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "没有提供要更新的字段"})
		return
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE user_id = ?", strings.Join(setParts, ", "))
	args = append(args, userID)

	result, err := mainDB.Exec(query, args...)
	if err != nil {
		log.Printf("Update user error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		logAdminAction("UPDATE", "users", userID, "Updated user details")
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "用户更新成功",
		"changes": rowsAffected,
	})
}

func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")

	// Get employee_id first
	var employeeID string
	err := mainDB.QueryRow("SELECT employee_id FROM users WHERE user_id = ?", userID).Scan(&employeeID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	} else if err != nil {
		log.Printf("Get employee_id error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户工號失败"})
		return
	}

	// Delete user
	result, err := mainDB.Exec("DELETE FROM users WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("Delete user error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除用户失败"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	logAdminAction("DELETE", "users", employeeID, "Deleted user")

	// Delete user-specific database file
	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", employeeID))
	if err := os.Remove(userDbPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Delete user DB error: %v", err)
		// Don't return error, user is already deleted
	} else {
		log.Printf("✅ User database file deleted: %s.db", employeeID)
	}

	c.JSON(http.StatusOK, gin.H{"message": "用户删除成功"})
}

// ==================== Logging Helpers ====================

func logAdminAction(action string, tableName string, recordID string, details string) {
	_, err := mainDB.Exec(`
		INSERT INTO admin_log (action, table_name, record_id, details)
		VALUES (?, ?, ?, ?)
	`, action, tableName, recordID, details)
	if err != nil {
		log.Printf("Failed to log admin action: %v", err)
	}
}

func logUserAction(userDb *sql.DB, action string, tableName string, recordID string, details string) {
	_, err := userDb.Exec(`
		INSERT INTO user_log (action, table_name, record_id, details)
		VALUES (?, ?, ?, ?)
	`, action, tableName, recordID, details)
	if err != nil {
		log.Printf("Failed to log user action: %v", err)
	}
}

// ==================== Utility Functions ====================

func nilIfEmpty(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

func nilIfZero(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

func nilIfZeroDate(nt sql.NullTime) *Date {
	if nt.Valid {
		d := Date{Time: nt.Time}
		return &d
	}
	return nil
}

func nilIfZeroTimestamp(nt sql.NullTime) *Timestamp {
	if nt.Valid {
		t := Timestamp{Time: nt.Time}
		return &t
	}
	return nil
}

func nilIfEmptyString(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

func getCalendarTagsHandler(c *gin.Context) {
	rows, err := mainDB.Query("SELECT date, is_holiday, shift_type, updated_at, comment FROM calendar_tags ORDER BY date")
	if err != nil {
		log.Printf("Get calendar tags error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取日历标签失败"})
		return
	}
	defer rows.Close()

	var tags []CalendarTag
	for rows.Next() {
		var tag CalendarTag
		var isHoliday bool
		var comment sql.NullString

		err := rows.Scan(&tag.Date, &isHoliday, &tag.ShiftType, &tag.UpdatedAt, &comment)
		if err != nil {
			log.Printf("Scan calendar tag error: %v", err)
			continue
		}

		// Convert boolean to int for JSON response
		if isHoliday {
			tag.IsHoliday = 1
		} else {
			tag.IsHoliday = 0
		}

		tag.Comment = nilIfEmptyString(comment)

		tags = append(tags, tag)
	}

	c.JSON(http.StatusOK, tags)
}

func getCalendarTagHandler(c *gin.Context) {
	date := c.Param("date")

	var tag CalendarTag
	var isHoliday bool
	var comment sql.NullString

	err := mainDB.QueryRow("SELECT date, is_holiday, shift_type, updated_at, comment FROM calendar_tags WHERE date = ?", date).Scan(
		&tag.Date, &isHoliday, &tag.ShiftType, &tag.UpdatedAt, &comment,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusOK, nil)
		return
	} else if err != nil {
		log.Printf("Get calendar tag error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取日历标签失败"})
		return
	}

	// Convert boolean to int for JSON response
	if isHoliday {
		tag.IsHoliday = 1
	} else {
		tag.IsHoliday = 0
	}

	tag.Comment = nilIfEmptyString(comment)

	c.JSON(http.StatusOK, tag)
}

func setCalendarTagHandler(c *gin.Context) {
	date := c.Param("date")

	var req struct {
		IsHoliday *bool   `json:"is_holiday"`
		ShiftType *string `json:"shift_type"`
		Comment   string  `json:"comment"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Check if date already exists
	var existingDate string
	err := mainDB.QueryRow("SELECT date FROM calendar_tags WHERE date = ?", date).Scan(&existingDate)

	if err == sql.ErrNoRows {
		// Insert new record
		isHoliday := false
		if req.IsHoliday != nil {
			isHoliday = *req.IsHoliday
		}

		_, err = mainDB.Exec(
			"INSERT INTO calendar_tags (date, is_holiday, shift_type, comment) VALUES (?, ?, ?, ?)",
			date, isHoliday, req.ShiftType, req.Comment,
		)
		if err != nil {
			log.Printf("Create calendar tag error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建日历标签失败"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "日历标签创建成功",
			"date":    date,
		})
		logAdminAction("CREATE", "calendar_tags", date, fmt.Sprintf("Holiday: %v, Shift: %v", isHoliday, req.ShiftType))
	} else if err != nil {
		log.Printf("Check calendar tag exists error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查日期失败"})
		return
	} else {
		// Update existing record
		setParts := []string{}
		args := []interface{}{}

		if req.IsHoliday != nil {
			setParts = append(setParts, "is_holiday = ?")
			args = append(args, *req.IsHoliday)
		}
		if req.ShiftType != nil {
			setParts = append(setParts, "shift_type = ?")
			args = append(args, *req.ShiftType)
		}
		if req.Comment != "" {
			setParts = append(setParts, "comment = ?")
			args = append(args, req.Comment)
		}

		if len(setParts) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "没有提供要更新的字段"})
			return
		}

		query := fmt.Sprintf("UPDATE calendar_tags SET %s WHERE date = ?", strings.Join(setParts, ", "))
		args = append(args, date)

		_, err = mainDB.Exec(query, args...)
		if err != nil {
			log.Printf("Update calendar tag error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新日历标签失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "日历标签更新成功",
			"date":    date,
		})

		shiftVal := "null"
		if req.ShiftType != nil {
			shiftVal = *req.ShiftType
		}
		logAdminAction("UPDATE", "calendar_tags", date, fmt.Sprintf("Holiday: %v, Shift: %v", req.IsHoliday, shiftVal))
	}
}

func deleteCalendarTagHandler(c *gin.Context) {
	date := c.Param("date")

	result, err := mainDB.Exec("DELETE FROM calendar_tags WHERE date = ?", date)
	if err != nil {
		log.Printf("Delete calendar tag error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除日历标签失败"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "日历标签不存在"})
		return
	}
	logAdminAction("DELETE", "calendar_tags", date, "Deleted calendar tag")

	c.JSON(http.StatusOK, gin.H{"message": "日历标签删除成功"})
}

func batchCalendarTagsHandler(c *gin.Context) {
	var req struct {
		Tags []struct {
			Date      string  `json:"date"`
			IsHoliday *bool   `json:"is_holiday"`
			ShiftType *string `json:"shift_type"`
			Comment   string  `json:"comment"`
		} `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if len(req.Tags) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的标签数组"})
		return
	}

	tx, err := mainDB.Begin()
	if err != nil {
		log.Printf("Begin transaction error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "开始事务失败"})
		return
	}
	defer tx.Rollback()

	var errors []map[string]interface{}
	successCount := 0

	for _, tag := range req.Tags {
		isHoliday := false
		if tag.IsHoliday != nil {
			isHoliday = *tag.IsHoliday
		}

		_, err = tx.Exec(`
			INSERT INTO calendar_tags (date, is_holiday, shift_type, comment)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(date) DO UPDATE SET
				is_holiday = excluded.is_holiday,
				shift_type = excluded.shift_type,
				comment = excluded.comment
		`, tag.Date, isHoliday, tag.ShiftType, tag.Comment)

		if err != nil {
			errors = append(errors, map[string]interface{}{
				"date":  tag.Date,
				"error": err.Error(),
			})
		} else {
			successCount++
		}
	}

	if err = tx.Commit(); err != nil {
		log.Printf("Commit transaction error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交事务失败"})
		return
	}

	if len(errors) > 0 {
		c.JSON(http.StatusPartialContent, gin.H{
			"message": "批量操作完成，但有部分失败",
			"errors":  errors,
			"success": successCount,
			"total":   len(req.Tags),
		})
		if successCount > 0 {
			logAdminAction("BATCH_UPDATE", "calendar_tags", "batch", fmt.Sprintf("Successfully batch updated %d tags out of %d", successCount, len(req.Tags)))
		}
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "批量操作成功",
			"count":   successCount,
		})
		logAdminAction("BATCH_UPDATE", "calendar_tags", "batch", fmt.Sprintf("Successfully batch updated all %d tags", successCount))
	}
}

func getShiftAssignmentsHandler(c *gin.Context) {
	employeeID := c.Param("employeeId")

	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", employeeID))

	// Check if user database exists
	if _, err := os.Stat(userDbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户数据库不存在"})
		return
	}

	userDb, err := sql.Open("sqlite", userDbPath)
	if err != nil {
		log.Printf("Open user DB error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "连接用户数据库失败"})
		return
	}
	defer userDb.Close()

	// Ensure shift_assignments table exists
	_, err = userDb.Exec(`
		CREATE TABLE IF NOT EXISTS shift_assignments (
			employee_id    TEXT NOT NULL,
			date           DATE NOT NULL,
			shift_type     TEXT NOT NULL,
			comment        TEXT,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (employee_id, date)
		)
	`)
	if err != nil {
		log.Printf("Create shift_assignments table error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建表失败"})
		return
	}

	// Ensure user_log table exists
	_, err = userDb.Exec(`
		CREATE TABLE IF NOT EXISTS user_log (
			log_id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			table_name TEXT NOT NULL,
			record_id TEXT NOT NULL,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("Create user_log table error: %v", err)
	}

	rows, err := userDb.Query("SELECT employee_id, date, shift_type, comment, created_at, updated_at FROM shift_assignments ORDER BY date")
	if err != nil {
		log.Printf("Get shift assignments error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取排班数据失败"})
		return
	}
	defer rows.Close()

	var assignments []ShiftAssignment
	for rows.Next() {
		var assignment ShiftAssignment
		var comment sql.NullString
		var createdAt, updatedAt sql.NullTime

		err := rows.Scan(&assignment.EmployeeID, &assignment.Date, &assignment.ShiftType, &comment, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("Scan shift assignment error: %v", err)
			continue
		}

		assignment.Comment = comment.String
		assignment.CreatedAt = nilIfZeroTimestamp(createdAt)
		assignment.UpdatedAt = nilIfZeroTimestamp(updatedAt)

		assignments = append(assignments, assignment)
	}

	c.JSON(http.StatusOK, assignments)
}

func setShiftAssignmentHandler(c *gin.Context) {
	employeeID := c.Param("employeeId")
	date := c.Param("date")

	var req struct {
		ShiftType string `json:"shift_type"`
		Comment   string `json:"comment"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.ShiftType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "排班类型为必填项"})
		return
	}

	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", employeeID))

	// Check if user database exists
	if _, err := os.Stat(userDbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户数据库不存在"})
		return
	}

	userDb, err := sql.Open("sqlite", userDbPath)
	if err != nil {
		log.Printf("Open user DB error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "连接用户数据库失败"})
		return
	}
	defer userDb.Close()

	// Ensure shift_assignments table exists
	_, err = userDb.Exec(`
		CREATE TABLE IF NOT EXISTS shift_assignments (
			employee_id    TEXT NOT NULL,
			date           DATE NOT NULL,
			shift_type     TEXT NOT NULL,
			comment        TEXT,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (employee_id, date)
		)
	`)
	if err != nil {
		log.Printf("Create shift_assignments table error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建表失败"})
		return
	}

	// Ensure user_log table exists
	_, err = userDb.Exec(`
		CREATE TABLE IF NOT EXISTS user_log (
			log_id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			table_name TEXT NOT NULL,
			record_id TEXT NOT NULL,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("Create user_log table error: %v", err)
	}

	// Insert or update shift assignment
	_, err = userDb.Exec(`
		INSERT INTO shift_assignments (employee_id, date, shift_type, comment)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(employee_id, date) DO UPDATE SET
			shift_type = excluded.shift_type,
			comment = excluded.comment,
			updated_at = CURRENT_TIMESTAMP
	`, employeeID, date, req.ShiftType, req.Comment)

	if err != nil {
		log.Printf("Save shift assignment error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存排班失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"employee_id": employeeID,
		"date":        date,
		"shift_type":  req.ShiftType,
		"comment":     req.Comment,
		"message":     "排班保存成功",
	})

	logUserAction(userDb, "UPSERT", "shift_assignments", date, fmt.Sprintf("Shift: %s, Comment: %s", req.ShiftType, req.Comment))
}

func deleteShiftAssignmentHandler(c *gin.Context) {
	employeeID := c.Param("employeeId")
	date := c.Param("date")

	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", employeeID))

	// Check if user database exists
	if _, err := os.Stat(userDbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户数据库不存在"})
		return
	}

	userDb, err := sql.Open("sqlite", userDbPath)
	if err != nil {
		log.Printf("Open user DB error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "连接用户数据库失败"})
		return
	}
	defer userDb.Close()

	result, err := userDb.Exec("DELETE FROM shift_assignments WHERE employee_id = ? AND date = ?", employeeID, date)
	if err != nil {
		log.Printf("Delete shift assignment error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除排班失败"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "排班不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "排班删除成功"})
	logUserAction(userDb, "DELETE", "shift_assignments", date, "Deleted shift assignment")
}

func moveShiftAssignmentHandler(c *gin.Context) {
	employeeID := c.Param("employeeId")

	var req struct {
		FromDate     string `json:"from_date"`
		ToEmployeeID string `json:"to_employee_id"`
		ToDate       string `json:"to_date"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.FromDate == "" || req.ToEmployeeID == "" || req.ToDate == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必要参数"})
		return
	}

	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", employeeID))

	// Check if user database exists
	if _, err := os.Stat(userDbPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户数据库不存在"})
		return
	}

	userDb, err := sql.Open("sqlite", userDbPath)
	if err != nil {
		log.Printf("Open user DB error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "连接用户数据库失败"})
		return
	}
	defer userDb.Close()

	// Get the shift to move
	var shiftType string
	err = userDb.QueryRow("SELECT shift_type FROM shift_assignments WHERE employee_id = ? AND date = ?", employeeID, req.FromDate).Scan(&shiftType)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "源排班不存在"})
		return
	} else if err != nil {
		log.Printf("Get shift assignment error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取排班失败"})
		return
	}

	// Check if target position already has an assignment
	var existingShift string
	err = userDb.QueryRow("SELECT shift_type FROM shift_assignments WHERE employee_id = ? AND date = ?", req.ToEmployeeID, req.ToDate).Scan(&existingShift)

	if err == sql.ErrNoRows {
		// Move to empty position
		_, err = userDb.Exec(`
			UPDATE shift_assignments SET employee_id = ?, date = ?, updated_at = CURRENT_TIMESTAMP
			WHERE employee_id = ? AND date = ?
		`, req.ToEmployeeID, req.ToDate, employeeID, req.FromDate)
		if err != nil {
			log.Printf("Move shift assignment error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "移动排班失败"})
			return
		}
	} else if err != nil {
		log.Printf("Check target position error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查目标位置失败"})
		return
	} else {
		// Swap assignments
		_, err = userDb.Exec(`
			UPDATE shift_assignments SET shift_type = ?, updated_at = CURRENT_TIMESTAMP
			WHERE employee_id = ? AND date = ?
		`, shiftType, req.ToEmployeeID, req.ToDate)
		if err != nil {
			log.Printf("Update target position error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新目标位置失败"})
			return
		}

		_, err = userDb.Exec(`
			UPDATE shift_assignments SET shift_type = ?, updated_at = CURRENT_TIMESTAMP
			WHERE employee_id = ? AND date = ?
		`, existingShift, employeeID, req.FromDate)
		if err != nil {
			log.Printf("Update source position error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新源位置失败"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "排班移动成功"})
	logUserAction(userDb, "MOVE_FROM", "shift_assignments", req.FromDate, fmt.Sprintf("Moved to %s %s", req.ToEmployeeID, req.ToDate))
}

func getLeaveTypesHandler(c *gin.Context) {
	rows, err := mainDB.Query("SELECT leave_id, name, is_not_workday, color, created_at FROM leave_types ORDER BY created_at DESC")
	if err != nil {
		log.Printf("Get leave types error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取请假类型失败"})
		return
	}
	defer rows.Close()

	var leaveTypes []LeaveType
	for rows.Next() {
		var leaveType LeaveType
		var isNotWorkday bool
		var createdAt sql.NullTime

		err := rows.Scan(&leaveType.LeaveID, &leaveType.Name, &isNotWorkday, &leaveType.Color, &createdAt)
		if err != nil {
			log.Printf("Scan leave type error: %v", err)
			continue
		}

		// Convert boolean to int for JSON response
		if isNotWorkday {
			leaveType.IsNotWorkday = 1
		} else {
			leaveType.IsNotWorkday = 0
		}
		leaveType.CreatedAt = nilIfZeroTimestamp(createdAt)

		leaveTypes = append(leaveTypes, leaveType)
	}

	c.JSON(http.StatusOK, leaveTypes)
}

func getLeaveTypeHandler(c *gin.Context) {
	leaveID := c.Param("id")

	var leaveType LeaveType
	var isNotWorkday bool
	var createdAt sql.NullTime

	err := mainDB.QueryRow("SELECT leave_id, name, is_not_workday, color, created_at FROM leave_types WHERE leave_id = ?", leaveID).Scan(
		&leaveType.LeaveID, &leaveType.Name, &isNotWorkday, &leaveType.Color, &createdAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "请假类型不存在"})
		return
	} else if err != nil {
		log.Printf("Get leave type error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取请假类型失败"})
		return
	}

	// Convert boolean to int for JSON response
	if isNotWorkday {
		leaveType.IsNotWorkday = 1
	} else {
		leaveType.IsNotWorkday = 0
	}
	leaveType.CreatedAt = nilIfZeroTimestamp(createdAt)

	c.JSON(http.StatusOK, leaveType)
}

func createLeaveTypeHandler(c *gin.Context) {
	var req struct {
		Name         string `json:"name"`
		IsNotWorkday *bool  `json:"is_not_workday"`
		Color        string `json:"color"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请假类型名稱為必填項"})
		return
	}

	// Check if name already exists
	var existingID int
	err := mainDB.QueryRow("SELECT leave_id FROM leave_types WHERE name = ?", req.Name).Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "此名稱已存在"})
		return
	} else if err != sql.ErrNoRows {
		log.Printf("Check name error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查名稱失败"})
		return
	}

	isNotWorkday := 0
	if req.IsNotWorkday != nil && *req.IsNotWorkday {
		isNotWorkday = 1
	}

	color := req.Color
	if color == "" {
		color = "#ff9800"
	}

	result, err := mainDB.Exec(
		"INSERT INTO leave_types (name, is_not_workday, color) VALUES (?, ?, ?)",
		req.Name, isNotWorkday, color,
	)
	if err != nil {
		log.Printf("Create leave type error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建请假类型失败"})
		return
	}

	leaveID, _ := result.LastInsertId()

	response := map[string]interface{}{
		"leave_id":       int(leaveID),
		"name":           req.Name,
		"is_not_workday": isNotWorkday,
		"color":          color,
	}

	c.JSON(http.StatusCreated, response)
	logAdminAction("CREATE", "leave_types", fmt.Sprintf("%d", leaveID), fmt.Sprintf("Created leave type: %s", req.Name))
}

func updateLeaveTypeHandler(c *gin.Context) {
	leaveID := c.Param("id")

	var req struct {
		Name         string `json:"name"`
		IsNotWorkday *bool  `json:"is_not_workday"`
		Color        string `json:"color"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Check if leave type exists
	var existingID int
	err := mainDB.QueryRow("SELECT leave_id FROM leave_types WHERE leave_id = ?", leaveID).Scan(&existingID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "请假类型不存在"})
		return
	} else if err != nil {
		log.Printf("Check leave type exists error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查请假类型失败"})
		return
	}

	// Check name conflict if provided
	if req.Name != "" {
		var conflictID int
		err := mainDB.QueryRow("SELECT leave_id FROM leave_types WHERE name = ? AND leave_id != ?", req.Name, leaveID).Scan(&conflictID)
		if err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "此名稱已被其他请假类型使用"})
			return
		} else if err != sql.ErrNoRows {
			log.Printf("Check name conflict error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "检查名稱冲突失败"})
			return
		}
	}

	// Build update query
	setParts := []string{}
	args := []interface{}{}

	if req.Name != "" {
		setParts = append(setParts, "name = ?")
		args = append(args, req.Name)
	}
	if req.IsNotWorkday != nil {
		isNotWorkday := 0
		if *req.IsNotWorkday {
			isNotWorkday = 1
		}
		setParts = append(setParts, "is_not_workday = ?")
		args = append(args, isNotWorkday)
	}
	if req.Color != "" {
		setParts = append(setParts, "color = ?")
		args = append(args, req.Color)
	}

	if len(setParts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "没有提供要更新的字段"})
		return
	}

	query := fmt.Sprintf("UPDATE leave_types SET %s WHERE leave_id = ?", strings.Join(setParts, ", "))
	args = append(args, leaveID)

	result, err := mainDB.Exec(query, args...)
	if err != nil {
		log.Printf("Update leave type error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新请假类型失败"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		logAdminAction("UPDATE", "leave_types", fmt.Sprintf("%v", leaveID), fmt.Sprintf("Updated leave type: %s", req.Name))
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "请假类型更新成功",
		"changes": rowsAffected,
	})
}

func deleteLeaveTypeHandler(c *gin.Context) {
	leaveID := c.Param("id")

	result, err := mainDB.Exec("DELETE FROM leave_types WHERE leave_id = ?", leaveID)
	if err != nil {
		log.Printf("Delete leave type error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除请假类型失败"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "请假类型不存在"})
		return
	}
	logAdminAction("DELETE", "leave_types", fmt.Sprintf("%v", leaveID), "Deleted leave type")

	c.JSON(http.StatusOK, gin.H{"message": "请假类型删除成功"})
}

func getLogsHandler(c *gin.Context) {
	var allLogs []LogEntry

	// 1. Get Admin Logs
	adminRows, err := mainDB.Query(`
		SELECT log_id, action, table_name, record_id, details, created_at 
		FROM admin_log
	`)
	if err != nil {
		log.Printf("Get admin logs error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取系统日志失败"})
		return
	}
	defer adminRows.Close()

	for adminRows.Next() {
		var l LogEntry
		var created sql.NullTime
		var details sql.NullString
		err := adminRows.Scan(&l.LogID, &l.Action, &l.TableName, &l.RecordID, &details, &created)
		if err == nil {
			l.User = "System Admin"
			l.Details = details.String
			l.CreatedAt = nilIfZeroTimestamp(created)
			allLogs = append(allLogs, l)
		}
	}

	// 2. Get User Logs
	userRows, err := mainDB.Query("SELECT employee_id, name FROM users")
	if err == nil {
		defer userRows.Close()
		for userRows.Next() {
			var empID string
			var empName string
			if err := userRows.Scan(&empID, &empName); err == nil {
				userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", empID))
				if _, err := os.Stat(userDbPath); err == nil {
					userDb, err := sql.Open("sqlite", userDbPath)
					if err == nil {
						uRows, err := userDb.Query(`
							SELECT log_id, action, table_name, record_id, details, created_at
							FROM user_log
						`)
						if err == nil {
							for uRows.Next() {
								var l LogEntry
								var created sql.NullTime
								var details sql.NullString
								err := uRows.Scan(&l.LogID, &l.Action, &l.TableName, &l.RecordID, &details, &created)
								if err == nil {
									l.User = fmt.Sprintf("%s (%s)", empName, empID)
									l.Details = details.String
									l.CreatedAt = nilIfZeroTimestamp(created)
									allLogs = append(allLogs, l)
								}
							}
							uRows.Close()
						}
						userDb.Close()
					}
				}
			}
		}
	}

	// Sorting logs manually by CreatedAt descending
	sort.Slice(allLogs, func(i, j int) bool {
		if allLogs[i].CreatedAt == nil {
			return false
		}
		if allLogs[j].CreatedAt == nil {
			return true
		}
		return allLogs[i].CreatedAt.Time.After(allLogs[j].CreatedAt.Time)
	})

	c.JSON(http.StatusOK, allLogs)
}
