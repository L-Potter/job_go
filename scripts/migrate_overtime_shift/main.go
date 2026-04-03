// 批次為各使用者 *.db 的 shift_assignments 表新增 overtime_shift TEXT 欄位（若尚不存在）。
// 用法（在專案根目錄）:
//
//	go run ./scripts/migrate_overtime_shift .
//
// 預設掃描參數目錄內所有 .db；僅處理已存在 shift_assignments 表的檔案。
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	dir := "../.."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		log.Fatal(err)
	}
	pattern := filepath.Join(abs, "*.db")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}
	if len(matches) == 0 {
		fmt.Printf("未找到符合 %s 的資料庫檔案\n", pattern)
		return
	}
	for _, path := range matches {
		if err := migrateFile(path); err != nil {
			log.Printf("失敗 %s: %v", path, err)
			continue
		}
		fmt.Println("OK", path)
	}
}

func migrateFile(path string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	defer db.Close()

	var n int
	err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='shift_assignments'`).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Println("略過（無 shift_assignments）", path)
		return nil
	}

	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('shift_assignments') WHERE name='overtime_shift'`).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Println("略過（已有 overtime_shift）", path)
		return nil
	}

	_, err = db.Exec(`ALTER TABLE shift_assignments ADD COLUMN overtime_shift TEXT`)
	return err
}
