package main

import (
	"context"
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

var (
	db  *sql.DB
	tpl *template.Template
)

type User struct {
	ID    int
	Email string
}

type Post struct {
	ID          int
	Title       string
	Content     string
	CreatedAt   string
	AuthorEmail string
	Categories  []string
	Likes       int
	Dislikes    int
}

type TemplateData struct {
	Theme string
	Posts []Post
	User  *User
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "forumx.db")
	if err != nil {
		log.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		log.Fatal(err)
	}

	tpl = template.Must(template.ParseFiles("index.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/posts", handlePosts)
	mux.HandleFunc("/about", staticHandler("About"))
	mux.HandleFunc("/terms", staticHandler("Terms"))
	mux.HandleFunc("/privacy", staticHandler("Privacy"))
	mux.HandleFunc("/forgot", staticHandler("Forgot"))
	mux.HandleFunc("/register", staticHandler("Register"))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", withSession(mux)))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	posts, err := loadPosts(r)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	data := TemplateData{
		Theme: themeFromCookie(r),
		Posts: posts,
		User:  currentUser(r),
	}
	if err := tpl.ExecuteTemplate(w, "index", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	var id int
	var hash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", email).Scan(&id, &hash)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	sid := uuid.New().String()
	exp := time.Now().Add(24 * time.Hour)
	_, err = db.Exec("INSERT INTO sessions(id, user_id, expires_at) VALUES(?,?,?)", sid, id, exp)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: sid, Path: "/", Expires: exp, HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handlePosts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		handleIndex(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	user := currentUser(r)
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	title := r.FormValue("title")
	content := r.FormValue("content")
	cats := r.Form["categories"]
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	res, err := tx.Exec("INSERT INTO posts(user_id, title, content) VALUES(?,?,?)", user.ID, title, content)
	if err != nil {
		tx.Rollback()
		http.Error(w, "server error", 500)
		return
	}
	pid, _ := res.LastInsertId()
	for _, c := range cats {
		tx.Exec("INSERT INTO post_categories(post_id, category) VALUES(?,?)", pid, c)
	}
	tx.Commit()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func staticHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(name))
	}
}

type userKey struct{}

func withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err == nil {
			var u User
			var expires time.Time
			err = db.QueryRow("SELECT users.id, users.email, sessions.expires_at FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.id = ?", cookie.Value).Scan(&u.ID, &u.Email, &expires)
			if err == nil && expires.After(time.Now()) {
				ctx := context.WithValue(r.Context(), userKey{}, &u)
				newExp := time.Now().Add(24 * time.Hour)
				db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", newExp, cookie.Value)
				http.SetCookie(w, &http.Cookie{Name: "session", Value: cookie.Value, Path: "/", Expires: newExp, HttpOnly: true})
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func currentUser(r *http.Request) *User {
	u, _ := r.Context().Value(userKey{}).(*User)
	return u
}

func themeFromCookie(r *http.Request) string {
	c, err := r.Cookie("theme")
	if err != nil {
		return "light"
	}
	if c.Value == "dark" {
		return "dark"
	}
	return "light"
}

func loadPosts(r *http.Request) ([]Post, error) {
	args := []interface{}{}
	q := `SELECT posts.id, posts.title, posts.content, posts.created_at, users.email,
           GROUP_CONCAT(post_categories.category) as categories,
           SUM(CASE WHEN likes.is_like=1 THEN 1 ELSE 0 END) as likes,
           SUM(CASE WHEN likes.is_like=0 THEN 1 ELSE 0 END) as dislikes
        FROM posts
        JOIN users ON posts.user_id = users.id
        LEFT JOIN post_categories ON posts.id = post_categories.post_id
        LEFT JOIN likes ON posts.id = likes.post_id`
	where := []string{}
	filter := r.URL.Query().Get("filter")
	if filter != "" {
		where = append(where, "posts.id IN (SELECT post_id FROM post_categories WHERE category = ?)")
		args = append(args, filter)
	}
	if r.URL.Query().Get("mine") == "true" {
		if u := currentUser(r); u != nil {
			where = append(where, "posts.user_id = ?")
			args = append(args, u.ID)
		} else {
			where = append(where, "1=0")
		}
	}
	if r.URL.Query().Get("liked") == "true" {
		if u := currentUser(r); u != nil {
			where = append(where, "posts.id IN (SELECT post_id FROM likes WHERE user_id = ? AND is_like = 1)")
			args = append(args, u.ID)
		} else {
			where = append(where, "1=0")
		}
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " GROUP BY posts.id ORDER BY posts.created_at DESC"
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var posts []Post
	for rows.Next() {
		var p Post
		var cats sql.NullString
		if err := rows.Scan(&p.ID, &p.Title, &p.Content, &p.CreatedAt, &p.AuthorEmail, &cats, &p.Likes, &p.Dislikes); err != nil {
			return nil, err
		}
		if cats.Valid {
			p.Categories = strings.Split(cats.String, ",")
		}
		posts = append(posts, p)
	}
	return posts, nil
}
