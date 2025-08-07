package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"
)

type userKey struct{}

type User struct {
	ID           int
	Email        string
	PasswordHash string
}

type Post struct {
	ID          int
	Title       string
	Content     string
	CreatedAt   time.Time
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

var (
	tpl      *template.Template
	mu       sync.Mutex
	users    = map[string]*User{}
	sessions = map[string]session{}
	posts    []Post
	nextUID  = 1
	nextPID  = 1
)

type session struct {
	user    *User
	expires time.Time
}

func main() {
	tpl = template.Must(template.ParseFiles("index.html"))
	users["test@example.com"] = &User{ID: nextUID, Email: "test@example.com", PasswordHash: hashPassword("password")}
	nextUID++

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
	ps, err := loadPosts(r)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	data := TemplateData{
		Theme: themeFromCookie(r),
		Posts: ps,
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
	mu.Lock()
	u, ok := users[email]
	if !ok || !checkPassword(u.PasswordHash, password) {
		mu.Unlock()
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	sid := newSessionID()
	exp := time.Now().Add(24 * time.Hour)
	sessions[sid] = session{user: u, expires: exp}
	mu.Unlock()
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
	mu.Lock()
	p := Post{
		ID:          nextPID,
		Title:       title,
		Content:     content,
		CreatedAt:   time.Now(),
		AuthorEmail: user.Email,
		Categories:  cats,
	}
	nextPID++
	posts = append(posts, p)
	mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func staticHandler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(name))
	}
}

func withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err == nil {
			mu.Lock()
			s, ok := sessions[cookie.Value]
			if ok && s.expires.After(time.Now()) {
				s.expires = time.Now().Add(24 * time.Hour)
				sessions[cookie.Value] = s
				ctx := context.WithValue(r.Context(), userKey{}, s.user)
				http.SetCookie(w, &http.Cookie{Name: "session", Value: cookie.Value, Path: "/", Expires: s.expires, HttpOnly: true})
				r = r.WithContext(ctx)
			}
			mu.Unlock()
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
	filter := r.URL.Query().Get("filter")
	mine := r.URL.Query().Get("mine") == "true"
	u := currentUser(r)
	mu.Lock()
	defer mu.Unlock()
	var out []Post
	for _, p := range posts {
		if filter != "" {
			found := false
			for _, c := range p.Categories {
				if c == filter {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if mine && (u == nil || p.AuthorEmail != u.Email) {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func newSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])
}

func checkPassword(hash, pw string) bool {
	return hash == hashPassword(pw)
}
