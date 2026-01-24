# Database Initialization Scripts

This directory contains scripts to initialize the SQLite database for the shift management application.

## Available Scripts

### Node.js Version (`initdb.js`)
- **Platform**: Cross-platform
- **Usage**: `node scripts/initdb.js`
- **Requirements**: Node.js, sqlite3 package

### Go Version (`initdb.go`)
- **Platform**: Cross-platform
- **Usage**:
  ```bash
  cd scripts
  go run initdb.go
  ```
- **Requirements**: Go 1.21+, CGO enabled for sqlite3
- **Features**:
  - Automatically sets database file as hidden on Windows (`attrib +h`)
  - Native performance
  - No external dependencies (except sqlite3 driver)

## Database Structure

The scripts create the following tables:

- `users`: User accounts with authentication
- `calendar_tags`: Calendar-specific configurations (holidays, shift types)
- `leave_types`: Available leave/absence types

## Default Data

Both scripts insert:
- Admin user: `admin` / `admin` (password hash)
- Default leave types: 事假, 病假, 特休, 加班

## Windows Hidden Files

The Go version automatically sets the database file as hidden on Windows systems using the `attrib +h` command.
