package internal

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type App struct {
	db  *sql.DB
	Tpl *Templater
}

func NewApp(db *sql.DB) *App {
	tpl, _ := NewTemplater()
	return &App{db: db, Tpl: tpl}
}

func (a *App) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/static/", http.StripPrefix("/static/", StaticFS()))
	mux.Handle("/", WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handleIndex)))))
	mux.Handle("/register", WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handleRegister)))))
	mux.Handle("/login", WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handleLogin)))))
	mux.Handle("/logout", WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handleLogout)))))
	mux.Handle("/posts/new", RequireAuth(WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handlePostNew))))))
	mux.Handle("/posts/create", RequireAuth(WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handlePostCreate))))))
	mux.Handle("/posts/", WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handlePostView)))))
	mux.Handle("/comments/create", RequireAuth(WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handleCommentCreate))))))
	mux.Handle("/react", RequireAuth(WithRecover(WithSecurityHeaders(WithUser(a.db, http.HandlerFunc(a.handleReact))))))
}

// Middleware for basic security and panic recovery
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func WithRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func(){ if rec := recover(); rec != nil { http.Error(w, "internal server error", http.StatusInternalServerError) } }()
		next.ServeHTTP(w, r)
	})
}

// Handlers

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	var currentID *int
	if u := UserFromRequest(r); u != nil { currentID = &u.ID }
	var catID *int
	if c := r.URL.Query().Get("category"); c != "" { if id, err := strconv.Atoi(c); err==nil { catID = &id } }
	filter := r.URL.Query().Get("filter") // "", "mine", "liked"
	posts, err := ListPosts(r.Context(), a.db, currentID, catID, filter)
	if err != nil { a.renderError(w, r, http.StatusInternalServerError, err); return }
	// list categories for filter UI
	rows, err := a.db.QueryContext(r.Context(), `SELECT id, name FROM categories ORDER BY name`)
	if err != nil { a.renderError(w,r, http.StatusInternalServerError, err); return }
	defer rows.Close()
	cats := []Category{}
	for rows.Next() { var c Category; if err := rows.Scan(&c.ID, &c.Name); err==nil { cats = append(cats, c) } }
	data := map[string]any{"User": UserFromRequest(r), "Posts": posts, "Categories": cats, "Filter": filter, "CatID": catID}
	a.Tpl.Render(w, "index.tmpl.html", data, http.StatusOK)
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.Tpl.Render(w, "auth_register.tmpl.html", map[string]any{"User": UserFromRequest(r)}, http.StatusOK); return
	}
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	email := strings.TrimSpace(r.FormValue("email"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if email=="" || username=="" || password=="" { a.renderError(w,r,http.StatusBadRequest,errors.New("all fields required")); return }
	hash, err := HashPassword(password)
	if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
	_, err = CreateUser(r.Context(), a.db, email, username, hash)
	if err != nil {
		// likely unique constraint violation
		a.renderError(w,r,http.StatusConflict, errors.New("email or username already taken")); return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.Tpl.Render(w, "auth_login.tmpl.html", map[string]any{"User": UserFromRequest(r), "Next": r.URL.Query().Get("next")}, http.StatusOK); return
	}
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	next := r.FormValue("next")
	u, err := GetUserByEmail(r.Context(), a.db, email)
	if err != nil { a.renderError(w,r,http.StatusUnauthorized, ErrBadCredentials); return }
	if err := CheckPassword(u.PasswordHash, password); err != nil { a.renderError(w,r,http.StatusUnauthorized, ErrBadCredentials); return }
	id, exp, err := CreateSession(r.Context(), a.db, u.ID)
	if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
	setSessionCookie(w, id, exp)
	if next == "" { next = "/" }
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	c, err := r.Cookie(SessionCookieName)
	if err == nil && c.Value != "" { _ = DeleteSession(r.Context(), a.db, c.Value) }
	clearCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handlePostNew(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id, name FROM categories ORDER BY name`)
	if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
	defer rows.Close()
	cats := []Category{}
	for rows.Next() { var c Category; if err := rows.Scan(&c.ID, &c.Name); err==nil { cats=append(cats,c) } }
	data := map[string]any{"User": UserFromRequest(r), "Categories": cats}
	a.Tpl.Render(w, "post_new.tmpl.html", data, http.StatusOK)
}

func (a *App) handlePostCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	u := UserFromRequest(r); if u == nil { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	title := strings.TrimSpace(r.FormValue("title"))
	content := strings.TrimSpace(r.FormValue("content"))
	catsStr := strings.TrimSpace(r.FormValue("categories")) // comma-separated new names
	catsSel := r.Form["category"] // selected existing ids
	if title=="" || content=="" { a.renderError(w,r,http.StatusBadRequest, errors.New("title and content required")); return }
	// Ensure new categories
	var catIDs []int
	if catsStr != "" {
		names := strings.Split(catsStr, ",")
		ensured, err := EnsureCategories(r.Context(), a.db, names)
		if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
		for _,c := range ensured { catIDs = append(catIDs, c.ID) }
	}
	for _, s := range catsSel { if id, err := strconv.Atoi(s); err==nil { catIDs = append(catIDs, id) } }
	pid, err := CreatePost(r.Context(), a.db, u.ID, title, content, catIDs)
	if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
	http.Redirect(w, r, fmt.Sprintf("/posts/%d", pid), http.StatusSeeOther)
}

func (a *App) handlePostView(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/posts/") { http.NotFound(w, r); return }
	id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/posts/"))
	if err != nil { http.NotFound(w, r); return }
	post, err := PostByID(r.Context(), a.db, id)
	if err != nil { a.renderError(w,r,http.StatusNotFound, errors.New("post not found")); return }
	comments, err := ListComments(r.Context(), a.db, id)
	if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
	data := map[string]any{"User": UserFromRequest(r), "Post": post, "Comments": comments}
	a.Tpl.Render(w, "post_view.tmpl.html", data, http.StatusOK)
}

func (a *App) handleCommentCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	u := UserFromRequest(r); if u == nil { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	postID, _ := strconv.Atoi(r.FormValue("post_id"))
	content := strings.TrimSpace(r.FormValue("content"))
	if content=="" { a.renderError(w,r,http.StatusBadRequest, errors.New("content required")); return }
	_, err := CreateComment(r.Context(), a.db, postID, u.ID, content)
	if err != nil { a.renderError(w,r,http.StatusInternalServerError, err); return }
	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusSeeOther)
}

func (a *App) handleReact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
	u := UserFromRequest(r); if u == nil { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	typeStr := r.FormValue("type")
	id, _ := strconv.Atoi(r.FormValue("id"))
	val, _ := strconv.Atoi(r.FormValue("value"))
	if err := React(r.Context(), a.db, u.ID, typeStr, id, val); err != nil { a.renderError(w,r,http.StatusBadRequest, err); return }
	// Redirect back
	referer := r.Header.Get("Referer"); if referer=="" { referer = "/" }
	http.Redirect(w, r, referer, http.StatusSeeOther)
}

func (a *App) renderError(w http.ResponseWriter, r *http.Request, status int, err error) {
	data := map[string]any{"User": UserFromRequest(r), "Status": status, "Error": err}
	a.Tpl.Render(w, "error.tmpl.html", data, status)
}