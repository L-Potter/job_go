# Job Shift Management Go Backend Server

This is the Go backend server for the Job Shift Management web application. It provides REST API endpoints for managing employees, shifts, leave records, and calendar tags using SQLite database.

## Features

- User authentication and management
- Shift assignment scheduling
- Calendar tag management (holidays, shift types)
- Leave type and record management
- Embedded static file serving for the React frontend

## Requirements

- Go 1.23.0 or later
- SQLite3

## Installation

1. Clone the repository and navigate to the server-go directory:
   ```bash
   cd server-go
   ```

2. Download dependencies:
   ```bash
   go mod download
   ```

3. Build the frontend (if not already built):
   - Navigate to the root project directory
   - Run `npm install` and `npm run build` to generate the `server-go/build/` directory

## Database Setup

The server uses a SQLite database located at `../database.db` (parent directory).

Make sure the database is initialized before running the server. You can use the initialization scripts in the `scripts/` directory.

## Running the Server

### Development Mode
```bash
go run main.go
```

### Build and Run
```bash
go build -o myapp main.go
./myapp
```

The server will start on `http://localhost:3001`

## API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### Users
- `GET /api/users` - Get all users
- `POST /api/users` - Create new user
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

### Calendar Tags
- `GET /api/calendar-tags` - Get all calendar tags
- `GET /api/calendar-tags/:date` - Get calendar tag by date
- `PUT /api/calendar-tags/:date` - Set/update calendar tag
- `DELETE /api/calendar-tags/:date` - Delete calendar tag
- `POST /api/calendar-tags/batch` - Batch update calendar tags

### Shift Assignments
- `GET /api/shift-assignments/:employeeId` - Get shift assignments for employee
- `PUT /api/shift-assignments/:employeeId/:date` - Set shift assignment
- `DELETE /api/shift-assignments/:employeeId/:date` - Delete shift assignment
- `POST /api/shift-assignments/:employeeId/move` - Move shift assignment

### Leave Types
- `GET /api/leave-types` - Get all leave types
- `GET /api/leave-types/:id` - Get leave type by ID
- `POST /api/leave-types` - Create leave type
- `PUT /api/leave-types/:id` - Update leave type
- `DELETE /api/leave-types/:id` - Delete leave type

## Static File Serving

The server serves the React frontend from the embedded `build/` directory at the root path `/`.

## Configuration

The server uses the following constants that can be modified in `main.go`:

- `PORT`: Server port (default: 3001)
- `HMAC_SECRET`: Secret key for password hashing
- `DB_PATH`: Database file path (default: "../database.db")
- `FRONTEND_URL`: Frontend URL for CORS (default: "http://localhost:5175")

## Dependencies

- [Gin](https://gin-gonic.com/) - Web framework
- [go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite driver
- [gorilla/mux](https://github.com/gorilla/mux) - HTTP router (indirect)
- [rs/cors](https://github.com/rs/cors) - CORS middleware (indirect)
