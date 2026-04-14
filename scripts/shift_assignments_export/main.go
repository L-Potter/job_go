// 在指定目錄以不分大小寫比對 {user}.db，讀取 shift_assignments 並將 date, shift_type, comment 輸出為 CSV。
//
// 用法:
//
//	go run . --path /Users/linchung/Desktop/cluade --user E144423
package main

import (
	"database/sql"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func printHelp(program string) {
	fmt.Fprintf(os.Stderr, `%s — 從使用者 SQLite 匯出 shift_assignments（CSV）

在 --path 目錄下尋找檔名為「{user}.db」的檔案（副檔名 .db、主檔名與 --user 比對時不分大小寫），
開啟後查詢資料表 shift_assignments，將下列欄位輸出至標準輸出（CSV）：
  date, shift_type, comment

選項:
`, program)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
範例:
  %s --path /Users/linchung/Desktop/cluade --user E144423

注意: 若目錄內有多個檔案主檔名與 --user 不分大小寫相同，將使用第一個符合者。
`, program)
}

func findUserDB(dir, user string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("讀取目錄: %w", err)
	}
	want := strings.TrimSpace(user)
	want = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(want), ".db"), ".DB")
	if want == "" {
		return "", fmt.Errorf("--user 不可為空")
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".db") {
			continue
		}
		base := strings.TrimSuffix(name, filepath.Ext(name))
		if strings.EqualFold(base, want) {
			matches = append(matches, filepath.Join(dir, name))
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("在 %q 找不到與 %q 對應的 .db（不分大小寫）", dir, want)
	}
	if len(matches) > 1 {
		fmt.Fprintf(os.Stderr, "警告: 多個符合的資料庫，使用: %s\n", matches[0])
	}
	return matches[0], nil
}

func main() {
	var (
		pathDir = flag.String("path", "", "要搜尋 *.db 的目錄絕對或相對路徑")
		user    = flag.String("user", "", "NT 帳號／工號（與檔名主檔名比對，不分大小寫，勿含 .db）")
		help    = flag.Bool("help", false, "顯示說明後結束")
	)

	flag.Usage = func() {
		printHelp(filepath.Base(os.Args[0]))
	}

	flag.Parse()

	if *help {
		printHelp(filepath.Base(os.Args[0]))
		os.Exit(0)
	}

	if strings.TrimSpace(*pathDir) == "" || strings.TrimSpace(*user) == "" {
		fmt.Fprintln(os.Stderr, "錯誤: 必須提供 --path 與 --user（或使用 --help）")
		flag.Usage()
		os.Exit(1)
	}

	absPath, err := filepath.Abs(*pathDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: %v\n", err)
		os.Exit(1)
	}

	dbPath, err := findUserDB(absPath, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: %v\n", err)
		os.Exit(1)
	}

	// modernc.org/sqlite 註冊為 driver 名稱 "sqlite"（與 server-go 相同）；唯讀避免與其他行程鎖衝突
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: 開啟資料庫: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: 無法連線資料庫: %v\n", err)
		os.Exit(1)
	}

	rows, err := db.Query(`
		SELECT date, shift_type, IFNULL(comment, '') AS comment
		FROM shift_assignments
		ORDER BY date
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: 查詢 shift_assignments: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := csv.NewWriter(os.Stdout)
	w.UseCRLF = false

	if err := w.Write([]string{"date", "shift_type", "comment"}); err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: 寫入 CSV 表頭: %v\n", err)
		os.Exit(1)
	}

	for rows.Next() {
		var dateStr, shiftType, comment string
		if err := rows.Scan(&dateStr, &shiftType, &comment); err != nil {
			fmt.Fprintf(os.Stderr, "錯誤: 讀取列: %v\n", err)
			os.Exit(1)
		}
		if err := w.Write([]string{dateStr, shiftType, comment}); err != nil {
			fmt.Fprintf(os.Stderr, "錯誤: 寫入 CSV: %v\n", err)
			os.Exit(1)
		}
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: 走訪結果: %v\n", err)
		os.Exit(1)
	}

	w.Flush()
	if err := w.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "錯誤: 輸出 CSV: %v\n", err)
		os.Exit(1)
	}
}
