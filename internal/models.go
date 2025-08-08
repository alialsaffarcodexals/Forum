package internal

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type User struct {
	ID int
	Email string
	Username string
	PasswordHash string
	CreatedAt time.Time
}

type Category struct { ID int; Name string }

type Post struct {
	ID int
	UserID int
	Title string
	Content string
	CreatedAt time.Time
	AuthorUsername string
	Likes int
	Dislikes int
	Score int
	Categories []Category
}

type Comment struct {
	ID int
	PostID int
	UserID int
	Content string
	CreatedAt time.Time
	AuthorUsername string
	Likes int
	Dislikes int
	Score int
}

// Data access helpers

func CreateUser(ctx context.Context, db *sql.DB, email, username, hash string) (int, error) {
	res, err := db.ExecContext(ctx, `INSERT INTO users(email, username, password_hash) VALUES(?,?,?)`, email, username, hash)
	if err != nil { return 0, err }
	id64, _ := res.LastInsertId()
	return int(id64), nil
}

func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (*User, error) {
	u := User{}
	row := db.QueryRowContext(ctx, `SELECT id, email, username, password_hash, created_at FROM users WHERE email=?`, email)
	if err := row.Scan(&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.CreatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func GetUserByID(ctx context.Context, db *sql.DB, id int) (*User, error) {
	u := User{}
	row := db.QueryRowContext(ctx, `SELECT id, email, username, password_hash, created_at FROM users WHERE id=?`, id)
	if err := row.Scan(&u.ID, &u.Email, &u.Username, &u.PasswordHash, &u.CreatedAt); err != nil { return nil, err }
	return &u, nil
}

func EnsureCategories(ctx context.Context, db *sql.DB, names []string) ([]Category, error) {
	out := make([]Category,0,len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" { continue }
		res, err := db.ExecContext(ctx, `INSERT INTO categories(name) VALUES(?) ON CONFLICT(name) DO NOTHING`, n)
		if err != nil { return nil, err }
		_ = res // ignore
	}
	rows, err := db.QueryContext(ctx, `SELECT id, name FROM categories WHERE name IN (`+placeholders(len(names))+`)`, anyify(names)...)
	if err != nil { return nil, err }
	defer rows.Close()
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.Name); err != nil { return nil, err }
		out = append(out, c)
	}
	return out, nil
}

func CreatePost(ctx context.Context, db *sql.DB, userID int, title, content string, categoryIDs []int) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil { return 0, err }
	defer func(){ if err!=nil { _ = tx.Rollback() } }()
	res, err := tx.ExecContext(ctx, `INSERT INTO posts(user_id, title, content) VALUES(?,?,?)`, userID, title, content)
	if err != nil { return 0, err }
	pid64, _ := res.LastInsertId()
	pid := int(pid64)
	for _, cid := range categoryIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO post_categories(post_id, category_id) VALUES(?,?)`, pid, cid); err != nil {
			return 0, err
		}
	}
	err = tx.Commit()
	return pid, err
}

func ListPosts(ctx context.Context, db *sql.DB, currentUserID *int, categoryID *int, filter string) ([]Post, error) {
	// Build WHERE conditions
	conds := []string{"1=1"}
	args := []any{}
	if categoryID != nil { conds = append(conds, "EXISTS (SELECT 1 FROM post_categories pc WHERE pc.post_id=p.id AND pc.category_id=?)"); args = append(args, *categoryID) }
	if filter == "mine" && currentUserID != nil { conds = append(conds, "p.user_id=?"); args = append(args, *currentUserID) }
	if filter == "liked" && currentUserID != nil {
		conds = append(conds, "EXISTS (SELECT 1 FROM reactions r WHERE r.user_id=? AND r.target_type='post' AND r.target_id=p.id AND r.value=1)")
		args = append(args, *currentUserID)
	}
	query := `SELECT p.id, p.user_id, p.title, p.content, p.created_at, u.username,
		COALESCE(ps.likes,0), COALESCE(ps.dislikes,0), COALESCE(ps.score,0)
		FROM posts p
		JOIN users u ON u.id=p.user_id
		LEFT JOIN post_scores ps ON ps.target_id = p.id
		WHERE ` + strings.Join(conds, " AND ") + `
		ORDER BY p.created_at DESC LIMIT 100`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.ID, &p.UserID, &p.Title, &p.Content, &p.CreatedAt, &p.AuthorUsername, &p.Likes, &p.Dislikes, &p.Score); err != nil { return nil, err }
		p.Categories, _ = PostCategories(ctx, db, p.ID)
		out = append(out, p)
	}
	return out, rows.Err()
}

func PostByID(ctx context.Context, db *sql.DB, id int) (*Post, error) {
	row := db.QueryRowContext(ctx, `SELECT p.id, p.user_id, p.title, p.content, p.created_at, u.username,
		COALESCE(ps.likes,0), COALESCE(ps.dislikes,0), COALESCE(ps.score,0)
		FROM posts p JOIN users u ON u.id=p.user_id
		LEFT JOIN post_scores ps ON ps.target_id = p.id
		WHERE p.id=?`, id)
	var p Post
	if err := row.Scan(&p.ID, &p.UserID, &p.Title, &p.Content, &p.CreatedAt, &p.AuthorUsername, &p.Likes, &p.Dislikes, &p.Score); err != nil {
		return nil, err
	}
	cats, _ := PostCategories(ctx, db, id)
	p.Categories = cats
	return &p, nil
}

func PostCategories(ctx context.Context, db *sql.DB, postID int) ([]Category, error) {
	rows, err := db.QueryContext(ctx, `SELECT c.id, c.name FROM categories c JOIN post_categories pc ON pc.category_id=c.id WHERE pc.post_id=? ORDER BY c.name`, postID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Category
	for rows.Next() { var c Category; if err := rows.Scan(&c.ID, &c.Name); err != nil { return nil, err }; out = append(out, c) }
	return out, rows.Err()
}

func ListComments(ctx context.Context, db *sql.DB, postID int) ([]Comment, error) {
	rows, err := db.QueryContext(ctx, `SELECT c.id, c.post_id, c.user_id, c.content, c.created_at, u.username,
		COALESCE(cs.likes,0), COALESCE(cs.dislikes,0), COALESCE(cs.score,0)
		FROM comments c JOIN users u ON u.id=c.user_id
		LEFT JOIN comment_scores cs ON cs.target_id=c.id
		WHERE c.post_id=? ORDER BY c.created_at ASC`, postID)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []Comment
	for rows.Next() {
		var cm Comment
		if err := rows.Scan(&cm.ID, &cm.PostID, &cm.UserID, &cm.Content, &cm.CreatedAt, &cm.AuthorUsername, &cm.Likes, &cm.Dislikes, &cm.Score); err != nil { return nil, err }
		out = append(out, cm)
	}
	return out, rows.Err()
}

func CreateComment(ctx context.Context, db *sql.DB, postID, userID int, content string) (int, error) {
	res, err := db.ExecContext(ctx, `INSERT INTO comments(post_id, user_id, content) VALUES(?,?,?)`, postID, userID, content)
	if err != nil { return 0, err }
	id64, _ := res.LastInsertId(); return int(id64), nil
}

func React(ctx context.Context, db *sql.DB, userID int, targetType string, targetID int, value int) error {
	if targetType != "post" && targetType != "comment" { return errors.New("invalid target type") }
	if value != -1 && value != 1 { return errors.New("invalid value") }
	_, err := db.ExecContext(ctx, `INSERT INTO reactions(user_id, target_type, target_id, value) VALUES(?,?,?,?)
		ON CONFLICT(user_id, target_type, target_id) DO UPDATE SET value=excluded.value`, userID, targetType, targetID, value)
	return err
}

// Utilities
func placeholders(n int) string { if n<=0 { return "" }; return strings.TrimRight(strings.Repeat("?,", n), ",") }
func anyify(ss []string) []any { out := make([]any,len(ss)); for i,s := range ss { out[i]=s }; return out }