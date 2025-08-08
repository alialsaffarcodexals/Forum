package internal

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func OpenDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil { return nil, err }
	db.SetMaxOpenConns(1)
	return db, nil
}

func ApplySchema(db *sql.DB, path string) error {
	b, err := os.ReadFile(path)
	if err != nil { return err }
	_, err = db.Exec(string(b))
	return err
}
