package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
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
	UserID                   int        `json:"user_id"`
	Name                     string     `json:"name"`
	EmployeeID               string     `json:"employee_id"`
	ShiftType                *string    `json:"shift_type"`
	Site                     *string    `json:"site"`
	DayNight                 *string    `json:"day_night"`
	Role                     string     `json:"role"`
	Group                    string     `json:"group"`
	MonthlyOvertimeCapHours  *int       `json:"monthly_overtime_cap_hours"`
	PasswordHash             string     `json:"-"`
	CreatedAt                *Timestamp `json:"created_at"`
	// 僅登入回應：供 admin/manager 呼叫待審註冊 API（Bearer），不來自資料庫欄位
	SessionToken string `json:"session_token,omitempty"`
}

// managerSession — 登入後發給 role 為 admin/manager 的 API token（記憶體儲存）
type managerSession struct {
	EmployeeID string
	Role       string
	Expires    time.Time
}

var managerSessions sync.Map // token -> managerSession

func newRandomAPIToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
}

// issueManagerSession 在成功登入後為任何角色發放 session token，
// 以便後端可從 Authorization 取得「作用者工號」寫入 admin_log。
// 實際的功能權限由各 API 另行以 requireAdminOrManagerAPI 判定。
func issueManagerSession(employeeID, role string) string {
	if employeeID == "" {
		return ""
	}
	token := newRandomAPIToken()
	managerSessions.Store(token, managerSession{
		EmployeeID: employeeID,
		Role:       role,
		Expires:    time.Now().Add(12 * time.Hour),
	})
	return token
}

func revokeManagerSession(token string) {
	if token != "" {
		managerSessions.Delete(token)
	}
}

func managerSessionFromRequest(c *gin.Context) (managerSession, bool) {
	h := c.GetHeader("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(h, pfx) {
		return managerSession{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, pfx))
	if token == "" {
		return managerSession{}, false
	}
	v, ok := managerSessions.Load(token)
	if !ok {
		return managerSession{}, false
	}
	s := v.(managerSession)
	if time.Now().After(s.Expires) {
		managerSessions.Delete(token)
		return managerSession{}, false
	}
	return s, true
}

func requireAdminOrManagerAPI(c *gin.Context) bool {
	s, ok := managerSessionFromRequest(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "請使用管理員或經理登入後取得的 session 存取此功能"})
		return false
	}
	if s.Role != "admin" && s.Role != "manager" {
		c.JSON(http.StatusForbidden, gin.H{"error": "僅限管理員或經理"})
		return false
	}
	return true
}

type CalendarTag struct {
	Date      Date    `json:"date"`
	IsHoliday int     `json:"is_holiday"`
	ShiftType *string `json:"shift_type"`
	Comment   *string `json:"comment"`
	UpdatedAt string  `json:"updated_at"`
}

type ShiftAssignment struct {
	EmployeeID    string     `json:"employee_id"`
	Date          Date       `json:"date"`
	ShiftType     string     `json:"shift_type"`
	Comment       string     `json:"comment"`
	OvertimeShift *string    `json:"overtime_shift"`
	CreatedAt     *Timestamp `json:"created_at"`
	UpdatedAt     *Timestamp `json:"updated_at"`
}

func isAllowedOvertimeShift(s string) bool {
	switch s {
	case "DA", "DB", "NA", "NB":
		return true
	default:
		return false
	}
}

// ensureShiftAssignmentsSchema 建立表並為舊庫補上 overtime_shift 欄位
func ensureShiftAssignmentsSchema(userDb *sql.DB) error {
	_, err := userDb.Exec(`
		CREATE TABLE IF NOT EXISTS shift_assignments (
			employee_id    TEXT NOT NULL,
			date           DATE NOT NULL,
			shift_type     TEXT NOT NULL,
			comment        TEXT,
			overtime_shift TEXT,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (employee_id, date)
		)
	`)
	if err != nil {
		return err
	}
	var n int
	err = userDb.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('shift_assignments') WHERE name = 'overtime_shift'`).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = userDb.Exec(`ALTER TABLE shift_assignments ADD COLUMN overtime_shift TEXT`)
	}
	return err
}

type LeaveType struct {
	LeaveID      int        `json:"leave_id"`
	Name         string     `json:"name"`
	IsNotWorkday int        `json:"is_not_workday"`
	Color        string     `json:"color"`
	CreatedAt    *Timestamp `json:"created_at"`
}

type LogEntry struct {
	LogID     int        `json:"log_id"`
	User      string     `json:"user"`
	Action    string     `json:"action"`
	TableName string     `json:"table_name"`
	RecordID  string     `json:"record_id"`
	Details   string     `json:"details"`
	CreatedAt *Timestamp `json:"created_at"`
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

	listenPort, err := findAvailableTCPPort(PORT)
	if err != nil {
		log.Fatal(err)
	}
	if listenPort != PORT {
		log.Printf("listen: port %d in use, using %d", PORT, listenPort)
	}
	log.Printf("API server: http://localhost:%d", listenPort)
	if err := router.Run(fmt.Sprintf(":%d", listenPort)); err != nil {
		log.Fatal(err)
	}
}

// findAvailableTCPPort probes from start with net.Listen; closes the probe so gin can bind the same port.
func findAvailableTCPPort(start int) (int, error) {
	if start < 1 || start > 65535 {
		return 0, fmt.Errorf("invalid start port: %d", start)
	}
	for p := start; p <= 65535; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			continue
		}
		if err := ln.Close(); err != nil {
			return 0, fmt.Errorf("close probe listener on %d: %w", p, err)
		}
		return p, nil
	}
	return 0, fmt.Errorf("no free TCP port in range %d-65535", start)
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
	return strings.Contains(lowerErr, "locked") || strings.Contains(lowerErr, "busy") || strings.Contains(lowerErr, "error")
}

func addRoutes(router *gin.Engine) {
	api := router.Group("/api")
	{
		// Auth routes
		api.POST("/login", loginHandler)
		api.POST("/logout", logoutHandler)
		api.POST("/change-password", changeOwnPasswordHandler)
		api.POST("/register", registerUserHandler)
		api.GET("/user-registrations", listUserRegistrationsHandler)
		api.POST("/user-registrations/:id/approve", approveUserRegistrationHandler)
		api.POST("/user-registrations/:id/reject", rejectUserRegistrationHandler)
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
		"group"                       TEXT NOT NULL DEFAULT '',
		monthly_overtime_cap_hours    INTEGER,
		created_at                    DATETIME DEFAULT CURRENT_TIMESTAMP
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
		log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
		actor_employee_id  TEXT,
		action             TEXT NOT NULL,
		table_name         TEXT NOT NULL,
		record_id          TEXT NOT NULL,
		details            TEXT,
		created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// 自助註冊（待 admin/manager 核准後寫入 users）
	userRegistrationsTable := `
	CREATE TABLE IF NOT EXISTS user_registrations (
		registration_id INTEGER PRIMARY KEY AUTOINCREMENT,
		name            TEXT NOT NULL,
		employee_id     TEXT NOT NULL,
		password_hash   TEXT NOT NULL,
		status          TEXT NOT NULL DEFAULT 'pending',
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	tables := []string{usersTable, calendarTagsTable, leaveTypesTable, adminLogTable, userRegistrationsTable}
	for _, table := range tables {
		_, err := db.Exec(table)
		if err != nil {
			return err
		}
	}

	if _, err := db.Exec(`ALTER TABLE users ADD COLUMN monthly_overtime_cap_hours INTEGER`); err != nil {
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already exists") {
			log.Printf("migrate users.monthly_overtime_cap_hours: %v", err)
		}
	}

	if _, err := db.Exec(`ALTER TABLE admin_log ADD COLUMN actor_employee_id TEXT`); err != nil {
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already exists") {
			log.Printf("migrate admin_log.actor_employee_id: %v", err)
		}
	}

	return nil
}

func hashPassword(password string) string {
	h := hmac.New(sha256.New, []byte(HMAC_SECRET))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// createEmployeeUserDatabase 建立 {employee_id}.db 及初始資料表（與 createUser 一致）
func createEmployeeUserDatabase(employeeID string) error {
	userDbPath := filepath.Join("..", fmt.Sprintf("%s.db", employeeID))
	userDb, err := sql.Open("sqlite", userDbPath)
	if err != nil {
		return fmt.Errorf("open user db: %w", err)
	}
	defer userDb.Close()

	if _, err := userDb.Exec(`
		CREATE TABLE IF NOT EXISTS leave_records (
			user_id        INTEGER NOT NULL,
			leave_type_id  INTEGER NOT NULL,
			date           DATE NOT NULL,
			total_hours    DECIMAL(4,2) NOT NULL,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("leave_records: %w", err)
	}
	if _, err := userDb.Exec(`
		CREATE TABLE IF NOT EXISTS user_log (
			log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
			actor_employee_id  TEXT,
			action             TEXT NOT NULL,
			table_name         TEXT NOT NULL,
			record_id          TEXT NOT NULL,
			details            TEXT,
			created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("user_log: %w", err)
	}
	log.Printf("✅ User database and tables created: %s.db", employeeID)
	cmd := exec.Command("attrib", "+h", userDbPath)
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to set hidden attribute on user DB: %v", err)
	}
	return nil
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
	var monthlyCap sql.NullInt64
	var createdAt sql.NullTime

	err := mainDB.QueryRow(`
		SELECT user_id, name, employee_id, shift_type, site, day_night, role, "group", monthly_overtime_cap_hours, created_at
		FROM users WHERE employee_id = ?
	`, req.EmployeeID).Scan(
		&user.UserID, &user.Name, &user.EmployeeID,
		&shiftType, &site, &dayNight, &user.Role, &user.Group, &monthlyCap, &createdAt,
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
	user.MonthlyOvertimeCapHours = intPtrFromNullInt64(monthlyCap)
	user.CreatedAt = nilIfZeroTimestamp(createdAt)

	user.SessionToken = issueManagerSession(user.EmployeeID, user.Role)

	c.JSON(http.StatusOK, user)
}

func logoutHandler(c *gin.Context) {
	var body struct {
		SessionToken string `json:"session_token"`
	}
	if c.Request.ContentLength > 0 {
		_ = c.ShouldBindJSON(&body)
	}
	revokeManagerSession(body.SessionToken)
	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
}

// changeOwnPasswordHandler — 已登入使用者憑工號＋目前密碼變更自己的密碼；寫入 admin_log（不含密碼明文）。
func changeOwnPasswordHandler(c *gin.Context) {
	var req struct {
		EmployeeID         string `json:"employee_id"`
		CurrentPassword    string `json:"current_password"`
		NewPassword        string `json:"new_password"`
		NewPasswordConfirm string `json:"new_password_confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.EmployeeID == "" || req.CurrentPassword == "" || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工號、目前密碼與新密碼為必填"})
		return
	}
	if req.NewPassword != req.NewPasswordConfirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "兩次輸入的新密碼不一致"})
		return
	}

	var userID int
	var name, passwordHash string
	err := mainDB.QueryRow(`
		SELECT user_id, name, password_hash FROM users WHERE employee_id = ?
	`, req.EmployeeID).Scan(&userID, &name, &passwordHash)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "工號或目前密碼錯誤"})
		return
	}
	if err != nil {
		log.Printf("change-password lookup: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "讀取帳號失敗"})
		return
	}

	if hashPassword(req.CurrentPassword) != passwordHash {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "工號或目前密碼錯誤"})
		return
	}

	newHash := hashPassword(req.NewPassword)
	res, err := mainDB.Exec(`UPDATE users SET password_hash = ? WHERE user_id = ?`, newHash, userID)
	if err != nil {
		log.Printf("change-password update: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新密碼失敗"})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新密碼失敗"})
		return
	}

	logAdminActionWithActor(
		req.EmployeeID,
		"SELF_PASSWORD_CHANGE",
		"users",
		req.EmployeeID,
		fmt.Sprintf("使用者自行變更密碼（工號:%s 姓名:%s）", req.EmployeeID, name),
	)
	_ = userID

	c.JSON(http.StatusOK, gin.H{"message": "密碼已更新"})
}

func registerUserHandler(c *gin.Context) {
	var req struct {
		Name            string `json:"name"`
		EmployeeID      string `json:"employee_id"`
		Password        string `json:"password"`
		PasswordConfirm string `json:"password_confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Name == "" || req.EmployeeID == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "姓名、工號和密碼為必填項"})
		return
	}
	if req.Password != req.PasswordConfirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "兩次輸入的密碼不一致"})
		return
	}

	var existing int
	err := mainDB.QueryRow("SELECT user_id FROM users WHERE employee_id = ?", req.EmployeeID).Scan(&existing)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "此工號已註冊為正式帳號"})
		return
	} else if err != sql.ErrNoRows {
		log.Printf("register check users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "註冊失敗"})
		return
	}

	var pendingID int
	err = mainDB.QueryRow(`
		SELECT registration_id FROM user_registrations
		WHERE employee_id = ? AND status = 'pending'
	`, req.EmployeeID).Scan(&pendingID)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "此工號已有待審核申請"})
		return
	} else if err != sql.ErrNoRows {
		log.Printf("register check pending: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "註冊失敗"})
		return
	}

	hash := hashPassword(req.Password)
	res, err := mainDB.Exec(`
		INSERT INTO user_registrations (name, employee_id, password_hash, status)
		VALUES (?, ?, ?, 'pending')
	`, req.Name, req.EmployeeID, hash)
	if err != nil {
		log.Printf("register insert: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "註冊失敗"})
		return
	}
	rid, _ := res.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"message":          "申請已送出，請待管理員核准後再登入",
		"registration_id": int(rid),
	})
}

func listUserRegistrationsHandler(c *gin.Context) {
	if !requireAdminOrManagerAPI(c) {
		return
	}
	rows, err := mainDB.Query(`
		SELECT registration_id, name, employee_id, created_at
		FROM user_registrations
		WHERE status = 'pending'
		ORDER BY created_at ASC
	`)
	if err != nil {
		log.Printf("list registrations: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "讀取待審清單失敗"})
		return
	}
	defer rows.Close()

	type row struct {
		RegistrationID int    `json:"registration_id"`
		Name             string `json:"name"`
		EmployeeID       string `json:"employee_id"`
		CreatedAt        string `json:"created_at"`
	}
	// 空清單須為 JSON []；nil slice 會變成 null，前端 pendingRegs.length 會拋錯
	out := make([]row, 0)
	for rows.Next() {
		var r row
		var createdAt sql.NullTime
		if err := rows.Scan(&r.RegistrationID, &r.Name, &r.EmployeeID, &createdAt); err != nil {
			continue
		}
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time.Format("2006-01-02 15:04:05")
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, out)
}

func approveUserRegistrationHandler(c *gin.Context) {
	if !requireAdminOrManagerAPI(c) {
		return
	}
	idStr := c.Param("id")
	regID, err := strconv.Atoi(idStr)
	if err != nil || regID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的申請編號"})
		return
	}

	tx, err := mainDB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "無法開始交易"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var name, employeeID, passwordHash string
	err = tx.QueryRow(`
		SELECT name, employee_id, password_hash
		FROM user_registrations
		WHERE registration_id = ? AND status = 'pending'
	`, regID).Scan(&name, &employeeID, &passwordHash)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "查無待審核申請"})
		return
	}
	if err != nil {
		log.Printf("approve load reg: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "讀取申請失敗"})
		return
	}

	var dup int
	err = tx.QueryRow("SELECT user_id FROM users WHERE employee_id = ?", employeeID).Scan(&dup)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "此工號已是正式使用者，請先拒絕或刪除重複申請"})
		return
	} else if err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "檢查工號失敗"})
		return
	}

	role := "user"
	group := ""
	shift := "A"
	site := "P1"
	dayNight := "D"

	res, err := tx.Exec(`
		INSERT INTO users (name, employee_id, password_hash, shift_type, site, day_night, role, "group")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, name, employeeID, passwordHash, shift, site, dayNight, role, group)
	if err != nil {
		log.Printf("approve insert user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "寫入 users 失敗"})
		return
	}
	userID, _ := res.LastInsertId()

	_, err = tx.Exec(`DELETE FROM user_registrations WHERE registration_id = ?`, regID)
	if err != nil {
		log.Printf("approve delete reg: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新申請狀態失敗"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("approve commit: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交失敗"})
		return
	}
	committed = true

	if err := createEmployeeUserDatabase(employeeID); err != nil {
		log.Printf("approve create db: %v", err)
		if _, e2 := mainDB.Exec("DELETE FROM users WHERE user_id = ?", userID); e2 != nil {
			log.Printf("approve rollback user cleanup: %v", e2)
		}
		if _, e2 := mainDB.Exec(`
			INSERT INTO user_registrations (name, employee_id, password_hash, status)
			VALUES (?, ?, ?, 'pending')
		`, name, employeeID, passwordHash); e2 != nil {
			log.Printf("approve restore registration failed: %v", e2)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "建立使用者資料庫失敗，已還原申請"})
		return
	}

	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"APPROVE_REG",
		"user_registrations",
		employeeID,
		fmt.Sprintf("核准註冊：%s（工號 %s，新 user_id=%d）", name, employeeID, userID),
	)

	c.JSON(http.StatusOK, gin.H{
		"user_id":      int(userID),
		"name":         name,
		"employee_id":  employeeID,
		"shift_type":   shift,
		"site":         site,
		"day_night":    dayNight,
		"role":         role,
		"group":        group,
		"message":      "已核准並建立帳號",
	})
}

func rejectUserRegistrationHandler(c *gin.Context) {
	if !requireAdminOrManagerAPI(c) {
		return
	}
	idStr := c.Param("id")
	regID, err := strconv.Atoi(idStr)
	if err != nil || regID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無效的申請編號"})
		return
	}
	res, err := mainDB.Exec(`DELETE FROM user_registrations WHERE registration_id = ? AND status = 'pending'`, regID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "拒絕失敗"})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "查無待審核申請"})
		return
	}
	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"REJECT_REG",
		"user_registrations",
		fmt.Sprint(regID),
		"拒絕註冊申請",
	)
	c.JSON(http.StatusOK, gin.H{"message": "已拒絕該筆申請"})
}

func getUsersHandler(c *gin.Context) {
	rows, err := mainDB.Query(`
		SELECT user_id, name, employee_id, shift_type, site, day_night, role, "group", monthly_overtime_cap_hours, created_at
		FROM users ORDER BY created_at DESC
	`)
	if err != nil {
		log.Printf("Get users error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户列表失败"})
		return
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var user User
		var shiftType, site, dayNight sql.NullString
		var monthlyCap sql.NullInt64
		var createdAt sql.NullTime

		err := rows.Scan(
			&user.UserID, &user.Name, &user.EmployeeID,
			&shiftType, &site, &dayNight, &user.Role, &user.Group, &monthlyCap, &createdAt,
		)
		if err != nil {
			log.Printf("Scan user error: %v", err)
			continue
		}

		user.ShiftType = nilIfEmpty(shiftType)
		user.Site = nilIfEmpty(site)
		user.DayNight = nilIfEmpty(dayNight)
		user.MonthlyOvertimeCapHours = intPtrFromNullInt64(monthlyCap)
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

	var monthlyCap sql.NullInt64
	err := mainDB.QueryRow(`
		SELECT user_id, name, employee_id, shift_type, site, day_night, role, "group", monthly_overtime_cap_hours, created_at
		FROM users WHERE user_id = ?
	`, userID).Scan(
		&user.UserID, &user.Name, &user.EmployeeID,
		&shiftType, &site, &dayNight, &user.Role, &user.Group, &monthlyCap, &createdAt,
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
	user.MonthlyOvertimeCapHours = intPtrFromNullInt64(monthlyCap)
	user.CreatedAt = nilIfZeroTimestamp(createdAt)

	c.JSON(http.StatusOK, user)
}

func createUserHandler(c *gin.Context) {
	var req struct {
		Name                     string  `json:"name"`
		EmployeeID               string  `json:"employee_id"`
		Password                 string  `json:"password"`
		ShiftType                *string `json:"shift_type"`
		Site                     *string `json:"site"`
		DayNight                 *string `json:"day_night"`
		Role                     string  `json:"role"`
		Group                    string  `json:"group"`
		MonthlyOvertimeCapHours  *int    `json:"monthly_overtime_cap_hours"`
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

	var cap interface{}
	if req.MonthlyOvertimeCapHours != nil {
		if *req.MonthlyOvertimeCapHours < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "monthly_overtime_cap_hours 不可為負數"})
			return
		}
		cap = *req.MonthlyOvertimeCapHours
	}

	result, err := mainDB.Exec(`
		INSERT INTO users (name, employee_id, password_hash, shift_type, site, day_night, role, "group", monthly_overtime_cap_hours)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.EmployeeID, passwordHash, req.ShiftType, req.Site, req.DayNight, role, req.Group, cap)

	if err != nil {
		log.Printf("Create user error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}

	userID, _ := result.LastInsertId()
	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"CREATE",
		"users",
		req.EmployeeID,
		fmt.Sprintf("建立員工：%s（工號 %s，角色 %s）", req.Name, req.EmployeeID, role),
	)

	if err := createEmployeeUserDatabase(req.EmployeeID); err != nil {
		log.Printf("Create user DB error: %v", err)
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
	if req.MonthlyOvertimeCapHours != nil {
		response["monthly_overtime_cap_hours"] = *req.MonthlyOvertimeCapHours
	} else {
		response["monthly_overtime_cap_hours"] = nil
	}

	c.JSON(http.StatusCreated, response)
}

func updateUserHandler(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Name                     string  `json:"name"`
		EmployeeID               string  `json:"employee_id"`
		ShiftType                *string `json:"shift_type"`
		Site                     *string `json:"site"`
		DayNight                 *string `json:"day_night"`
		Role                     string  `json:"role"`
		Group                    *string `json:"group"`
		Password                 string  `json:"password"`
		MonthlyOvertimeCapHours  *int    `json:"monthly_overtime_cap_hours"`
		ClearMonthlyOvertimeCap  *bool   `json:"clear_monthly_overtime_cap"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Check if user exists; also fetch current identifiers for logging
	var existingID int
	var existingEmployeeID, existingName string
	err := mainDB.QueryRow(
		`SELECT user_id, employee_id, name FROM users WHERE user_id = ?`, userID,
	).Scan(&existingID, &existingEmployeeID, &existingName)
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
	if req.ClearMonthlyOvertimeCap != nil && *req.ClearMonthlyOvertimeCap {
		setParts = append(setParts, "monthly_overtime_cap_hours = NULL")
	} else if req.MonthlyOvertimeCapHours != nil {
		if *req.MonthlyOvertimeCapHours < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "monthly_overtime_cap_hours 不可為負數"})
			return
		}
		setParts = append(setParts, "monthly_overtime_cap_hours = ?")
		args = append(args, *req.MonthlyOvertimeCapHours)
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
		actor := actorEmployeeIDFromContext(c)
		// 以實際的 employee_id 作為 record_id（與 CREATE/DELETE 一致），新工號若有變更則以新值為主。
		targetEmpID := existingEmployeeID
		if req.EmployeeID != "" {
			targetEmpID = req.EmployeeID
		}
		// 彙整被異動的欄位，便於稽核。
		changed := []string{}
		if req.Name != "" && req.Name != existingName {
			changed = append(changed, fmt.Sprintf("姓名→%s", req.Name))
		}
		if req.EmployeeID != "" && req.EmployeeID != existingEmployeeID {
			changed = append(changed, fmt.Sprintf("工號→%s", req.EmployeeID))
		}
		if req.ShiftType != nil {
			changed = append(changed, fmt.Sprintf("shift_type→%s", *req.ShiftType))
		}
		if req.Site != nil {
			changed = append(changed, fmt.Sprintf("site→%s", *req.Site))
		}
		if req.DayNight != nil {
			changed = append(changed, fmt.Sprintf("day_night→%s", *req.DayNight))
		}
		if req.Role != "" {
			changed = append(changed, fmt.Sprintf("role→%s", req.Role))
		}
		if req.Group != nil {
			changed = append(changed, fmt.Sprintf("group→%s", *req.Group))
		}
		if req.ClearMonthlyOvertimeCap != nil && *req.ClearMonthlyOvertimeCap {
			changed = append(changed, "monthly_overtime_cap_hours→(恢復預設)")
		} else if req.MonthlyOvertimeCapHours != nil {
			changed = append(changed, fmt.Sprintf("monthly_overtime_cap_hours→%d", *req.MonthlyOvertimeCapHours))
		}

		// 密碼若有變更，另外單獨記錄一筆，方便稽核。
		if req.Password != "" {
			logAdminActionWithActor(
				actor,
				"ADMIN_PASSWORD_CHANGE",
				"users",
				targetEmpID,
				fmt.Sprintf("管理員變更密碼（對象工號:%s 姓名:%s）", targetEmpID, existingName),
			)
		}

		detailSummary := fmt.Sprintf("更新員工（對象工號:%s 姓名:%s）", targetEmpID, existingName)
		if len(changed) > 0 {
			detailSummary += "；異動欄位：" + strings.Join(changed, ", ")
		}
		logAdminActionWithActor(actor, "UPDATE", "users", targetEmpID, detailSummary)
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
	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"DELETE",
		"users",
		employeeID,
		fmt.Sprintf("刪除員工（工號 %s）", employeeID),
	)

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

// nowLocalString 以伺服器本機時區（例：Asia/Taipei）回傳 "YYYY-MM-DD HH:MM:SS" 字串。
// SQLite 內建 CURRENT_TIMESTAMP 永遠是 UTC，會造成畫面上顯示的時間與實際操作時間差 8 小時，
// 因此 log 寫入時一律改由 Go 端帶入本機時間字串。
func nowLocalString() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

/**
 * 寫入 admin_log。actorEmployeeID 為實際操作者的工號（未登入或系統自動寫入請傳空字串）。
 * recordID 建議統一使用業務主鍵（例如 users 表請使用 employee_id、calendar_tags 使用日期字串）。
 */
func logAdminActionWithActor(actorEmployeeID, action, tableName, recordID, details string) {
	_, err := mainDB.Exec(`
		INSERT INTO admin_log (actor_employee_id, action, table_name, record_id, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, actorEmployeeID, action, tableName, recordID, details, nowLocalString())
	if err != nil {
		log.Printf("Failed to log admin action: %v", err)
	}
}

func logAdminAction(action string, tableName string, recordID string, details string) {
	logAdminActionWithActor("", action, tableName, recordID, details)
}

// actorEmployeeIDFromContext 從 Authorization bearer 對應的 managerSession 取得操作者工號。
// 未登入或 session 無效時回傳空字串（由呼叫端自行決定是否以空字串記錄）。
func actorEmployeeIDFromContext(c *gin.Context) string {
	if s, ok := managerSessionFromRequest(c); ok {
		return s.EmployeeID
	}
	return ""
}

// ensureUserLogSchema 確保使用者個人資料庫的 user_log 表存在，
// 並為舊庫補上 actor_employee_id 欄位以記錄「實際操作者」。
func ensureUserLogSchema(userDb *sql.DB) {
	if _, err := userDb.Exec(`
		CREATE TABLE IF NOT EXISTS user_log (
			log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
			actor_employee_id  TEXT,
			action             TEXT NOT NULL,
			table_name         TEXT NOT NULL,
			record_id          TEXT NOT NULL,
			details            TEXT,
			created_at         DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		log.Printf("ensureUserLogSchema create: %v", err)
	}
	if _, err := userDb.Exec(`ALTER TABLE user_log ADD COLUMN actor_employee_id TEXT`); err != nil {
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "duplicate") && !strings.Contains(low, "already exists") {
			log.Printf("ensureUserLogSchema migrate: %v", err)
		}
	}
}

// logUserActionWithActor 寫入個人資料庫的 user_log；actorEmployeeID 為代為填寫的實際操作者。
// 若該個人資料庫就是當事人自己所填，actorEmployeeID 可與資料庫擁有者相同或留空。
func logUserActionWithActor(userDb *sql.DB, actorEmployeeID, action, tableName, recordID, details string) {
	ensureUserLogSchema(userDb)
	_, err := userDb.Exec(`
		INSERT INTO user_log (actor_employee_id, action, table_name, record_id, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, actorEmployeeID, action, tableName, recordID, details, nowLocalString())
	if err != nil {
		log.Printf("Failed to log user action: %v", err)
	}
}

func logUserAction(userDb *sql.DB, action string, tableName string, recordID string, details string) {
	logUserActionWithActor(userDb, "", action, tableName, recordID, details)
}

// ==================== Utility Functions ====================

func intPtrFromNullInt64(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

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
		logAdminActionWithActor(
			actorEmployeeIDFromContext(c),
			"CREATE",
			"calendar_tags",
			date,
			fmt.Sprintf("建立行事曆標記（日期 %s，假日:%v，班別:%v）", date, isHoliday, req.ShiftType),
		)
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
		holidayDesc := "未變更"
		if req.IsHoliday != nil {
			holidayDesc = fmt.Sprintf("%v", *req.IsHoliday)
		}
		logAdminActionWithActor(
			actorEmployeeIDFromContext(c),
			"UPDATE",
			"calendar_tags",
			date,
			fmt.Sprintf("更新行事曆標記（日期 %s，假日:%s，班別:%s）", date, holidayDesc, shiftVal),
		)
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
	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"DELETE",
		"calendar_tags",
		date,
		fmt.Sprintf("刪除行事曆標記（日期 %s）", date),
	)

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
			logAdminActionWithActor(
				actorEmployeeIDFromContext(c),
				"BATCH_UPDATE",
				"calendar_tags",
				"batch",
				fmt.Sprintf("批次更新行事曆：成功 %d 筆／共 %d 筆", successCount, len(req.Tags)),
			)
		}
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "批量操作成功",
			"count":   successCount,
		})
		logAdminActionWithActor(
			actorEmployeeIDFromContext(c),
			"BATCH_UPDATE",
			"calendar_tags",
			"batch",
			fmt.Sprintf("批次更新行事曆：全部成功 %d 筆", successCount),
		)
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

	if err := ensureShiftAssignmentsSchema(userDb); err != nil {
		log.Printf("shift_assignments schema error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建表失败"})
		return
	}

	ensureUserLogSchema(userDb)

	rows, err := userDb.Query("SELECT employee_id, date, shift_type, comment, overtime_shift, created_at, updated_at FROM shift_assignments ORDER BY date")
	if err != nil {
		log.Printf("Get shift assignments error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取排班数据失败"})
		return
	}
	defer rows.Close()

	assignments := make([]ShiftAssignment, 0)
	for rows.Next() {
		var assignment ShiftAssignment
		var comment sql.NullString
		var overtimeShift sql.NullString
		var createdAt, updatedAt sql.NullTime

		err := rows.Scan(&assignment.EmployeeID, &assignment.Date, &assignment.ShiftType, &comment, &overtimeShift, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("Scan shift assignment error: %v", err)
			continue
		}

		assignment.Comment = comment.String
		if overtimeShift.Valid {
			s := overtimeShift.String
			assignment.OvertimeShift = &s
		}
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
		ShiftType     string  `json:"shift_type"`
		Comment       string  `json:"comment"`
		OvertimeShift *string `json:"overtime_shift"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.ShiftType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "排班类型为必填项"})
		return
	}

	var overtimeShift sql.NullString
	if req.OvertimeShift != nil && *req.OvertimeShift != "" {
		if !isAllowedOvertimeShift(*req.OvertimeShift) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "overtime_shift 僅能為 DA、DB、NA、NB 或省略"})
			return
		}
		overtimeShift = sql.NullString{String: *req.OvertimeShift, Valid: true}
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

	if err := ensureShiftAssignmentsSchema(userDb); err != nil {
		log.Printf("shift_assignments schema error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建表失败"})
		return
	}

	ensureUserLogSchema(userDb)

	now := time.Now().Format("2006-01-02 15:04:05")
	_, err = userDb.Exec(`
		INSERT INTO shift_assignments (employee_id, date, shift_type, comment, overtime_shift, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(employee_id, date) DO UPDATE SET
			shift_type = excluded.shift_type,
			comment = excluded.comment,
			overtime_shift = excluded.overtime_shift,
			updated_at = ?
	`, employeeID, date, req.ShiftType, req.Comment, overtimeShift, now, now, now)

	if err != nil {
		log.Printf("Save shift assignment error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存排班失败"})
		return
	}

	resp := gin.H{
		"employee_id": employeeID,
		"date":        date,
		"shift_type":  req.ShiftType,
		"comment":     req.Comment,
		"message":     "排班保存成功",
	}
	if overtimeShift.Valid {
		s := overtimeShift.String
		resp["overtime_shift"] = s
	} else {
		resp["overtime_shift"] = nil
	}

	c.JSON(http.StatusOK, resp)

	otLog := ""
	if overtimeShift.Valid {
		otLog = "，跨班加班:" + overtimeShift.String
	}
	logUserActionWithActor(
		userDb,
		actorEmployeeIDFromContext(c),
		"UPSERT",
		"shift_assignments",
		date,
		fmt.Sprintf("假別:%s，備註:%s%s", req.ShiftType, req.Comment, otLog),
	)
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
	logUserActionWithActor(
		userDb,
		actorEmployeeIDFromContext(c),
		"DELETE",
		"shift_assignments",
		date,
		"刪除排班",
	)
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

	if err := ensureShiftAssignmentsSchema(userDb); err != nil {
		log.Printf("shift_assignments schema error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "迁移表结构失败"})
		return
	}

	var shiftType string
	var srcOT sql.NullString
	err = userDb.QueryRow("SELECT shift_type, overtime_shift FROM shift_assignments WHERE employee_id = ? AND date = ?", employeeID, req.FromDate).Scan(&shiftType, &srcOT)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "源排班不存在"})
		return
	} else if err != nil {
		log.Printf("Get shift assignment error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取排班失败"})
		return
	}

	var existingShift string
	var tgtOT sql.NullString
	err = userDb.QueryRow("SELECT shift_type, overtime_shift FROM shift_assignments WHERE employee_id = ? AND date = ?", req.ToEmployeeID, req.ToDate).Scan(&existingShift, &tgtOT)

	if err == sql.ErrNoRows {
		now := time.Now().Format("2006-01-02 15:04:05")
		_, err = userDb.Exec(`
			UPDATE shift_assignments SET employee_id = ?, date = ?, updated_at = ?
			WHERE employee_id = ? AND date = ?
		`, req.ToEmployeeID, req.ToDate, now, employeeID, req.FromDate)
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
		now := time.Now().Format("2006-01-02 15:04:05")
		_, err = userDb.Exec(`
			UPDATE shift_assignments SET shift_type = ?, overtime_shift = ?, updated_at = ?
			WHERE employee_id = ? AND date = ?
		`, shiftType, srcOT, now, req.ToEmployeeID, req.ToDate)
		if err != nil {
			log.Printf("Update target position error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新目标位置失败"})
			return
		}

		_, err = userDb.Exec(`
			UPDATE shift_assignments SET shift_type = ?, overtime_shift = ?, updated_at = ?
			WHERE employee_id = ? AND date = ?
		`, existingShift, tgtOT, now, employeeID, req.FromDate)
		if err != nil {
			log.Printf("Update source position error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新源位置失败"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "排班移动成功"})
	logUserActionWithActor(
		userDb,
		actorEmployeeIDFromContext(c),
		"MOVE_FROM",
		"shift_assignments",
		req.FromDate,
		fmt.Sprintf("搬移至 %s 的 %s", req.ToEmployeeID, req.ToDate),
	)
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
	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"CREATE",
		"leave_types",
		req.Name,
		fmt.Sprintf("建立假別：%s（leave_id=%d，is_not_workday=%d，color=%s）", req.Name, leaveID, isNotWorkday, color),
	)
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
		changed := []string{}
		if req.Name != "" {
			changed = append(changed, fmt.Sprintf("名稱→%s", req.Name))
		}
		if req.IsNotWorkday != nil {
			changed = append(changed, fmt.Sprintf("is_not_workday→%v", *req.IsNotWorkday))
		}
		if req.Color != "" {
			changed = append(changed, fmt.Sprintf("color→%s", req.Color))
		}
		detailSummary := fmt.Sprintf("更新假別（leave_id=%s）", leaveID)
		if len(changed) > 0 {
			detailSummary += "；異動：" + strings.Join(changed, ", ")
		}
		logAdminActionWithActor(
			actorEmployeeIDFromContext(c),
			"UPDATE",
			"leave_types",
			leaveID,
			detailSummary,
		)
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
	logAdminActionWithActor(
		actorEmployeeIDFromContext(c),
		"DELETE",
		"leave_types",
		leaveID,
		fmt.Sprintf("刪除假別（leave_id=%s）", leaveID),
	)

	c.JSON(http.StatusOK, gin.H{"message": "请假类型删除成功"})
}

func getLogsHandler(c *gin.Context) {
	allLogs := make([]LogEntry, 0)

	// 1. Get Admin Logs（LEFT JOIN users 取得作用者姓名，actor_employee_id 為舊資料時可能為空）
	adminRows, err := mainDB.Query(`
		SELECT al.log_id, al.action, al.table_name, al.record_id, al.details, al.created_at,
		       al.actor_employee_id, u.name AS actor_name
		FROM admin_log al
		LEFT JOIN users u ON u.employee_id = al.actor_employee_id
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
		var actorEmp sql.NullString
		var actorName sql.NullString
		err := adminRows.Scan(&l.LogID, &l.Action, &l.TableName, &l.RecordID, &details, &created, &actorEmp, &actorName)
		if err == nil {
			switch {
			case actorName.Valid && actorName.String != "" && actorEmp.Valid && actorEmp.String != "":
				l.User = fmt.Sprintf("%s (%s)", actorName.String, actorEmp.String)
			case actorEmp.Valid && actorEmp.String != "":
				l.User = actorEmp.String
			default:
				l.User = "System Admin"
			}
			l.Details = details.String
			l.CreatedAt = nilIfZeroTimestamp(created)
			allLogs = append(allLogs, l)
		}
	}

	// 2. Get User Logs
	// 先建立 employee_id → name 的索引表，供 actor 名稱查詢使用（避免多次 DB 查詢）
	actorNameByEmpID := make(map[string]string)
	if nameRows, err := mainDB.Query("SELECT employee_id, name FROM users"); err == nil {
		for nameRows.Next() {
			var empID, empName string
			if err := nameRows.Scan(&empID, &empName); err == nil {
				actorNameByEmpID[empID] = empName
			}
		}
		nameRows.Close()
	}

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
						// 確保欄位齊全（舊庫會缺 actor_employee_id）
						ensureUserLogSchema(userDb)
						uRows, err := userDb.Query(`
							SELECT log_id, action, table_name, record_id, details, created_at, actor_employee_id
							FROM user_log
						`)
						if err == nil {
							for uRows.Next() {
								var l LogEntry
								var created sql.NullTime
								var details sql.NullString
								var actorEmp sql.NullString
								err := uRows.Scan(&l.LogID, &l.Action, &l.TableName, &l.RecordID, &details, &created, &actorEmp)
								if err == nil {
									// 作用者：優先顯示實際操作者；舊資料無 actor 時退回 DB 擁有者
									if actorEmp.Valid && actorEmp.String != "" {
										if name, ok := actorNameByEmpID[actorEmp.String]; ok && name != "" {
											l.User = fmt.Sprintf("%s (%s)", name, actorEmp.String)
										} else {
											l.User = actorEmp.String
										}
									} else {
										l.User = fmt.Sprintf("%s (%s)", empName, empID)
									}

									// 說明：明確帶出「對象：DB 擁有者」，原 details 附在後方
									target := fmt.Sprintf("%s (%s)", empName, empID)
									if details.Valid && details.String != "" {
										l.Details = fmt.Sprintf("對象 %s；%s", target, details.String)
									} else {
										l.Details = fmt.Sprintf("對象 %s", target)
									}

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
