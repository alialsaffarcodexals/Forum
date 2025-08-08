package internal

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "session_id"
	SessionDuration   = 7 * 24 * time.Hour // one week
)

type contextKey string

var ctxUserKey = contextKey("user")

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) error { return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) }

func CreateSession(ctx context.Context, db *sql.DB, userID int) (string, time.Time, error) {
	id := uuid.Must(uuid.NewV4()).String()
	exp := time.Now().Add(SessionDuration).UTC()
	// Only one open session per user (unique index). New login replaces old.
	_, err := db.ExecContext(ctx, `INSERT INTO sessions(id, user_id, expires_at) VALUES(?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET id=excluded.id, expires_at=excluded.expires_at, created_at=CURRENT_TIMESTAMP`, id, userID, exp)
	return id, exp, err
}

func DeleteSession(ctx context.Context, db *sql.DB, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id)
	return err
}

func UserFromRequest(r *http.Request) *User {
	v := r.Context().Value(ctxUserKey)
	if v == nil { return nil }
	u, _ := v.(*User); return u
}

func WithUser(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		var uid int
		var exp time.Time
		err = db.QueryRowContext(r.Context(), `SELECT user_id, expires_at FROM sessions WHERE id=?`, cookie.Value).Scan(&uid, &exp)
		if err != nil || time.Now().After(exp) {
			// invalid/expired session -> cleanup and clear cookie
			_ = DeleteSession(r.Context(), db, cookie.Value)
			clearCookie(w)
			next.ServeHTTP(w, r)
			return
		}
		u, err := GetUserByID(r.Context(), db, uid)
		if err != nil {
			next.ServeHTTP(w, r); return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey, u)))
	})
}

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromRequest(r) == nil { http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusSeeOther); return }
		next.ServeHTTP(w, r)
	})
}

func setSessionCookie(w http.ResponseWriter, id string, exp time.Time) {
	c := &http.Cookie{Name: SessionCookieName, Value: id, Path: "/", Expires: exp, HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode}
	http.SetCookie(w, c)
}

func clearCookie(w http.ResponseWriter) {
	c := &http.Cookie{Name: SessionCookieName, Value: "", Path: "/", Expires: time.Unix(0,0), MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	http.SetCookie(w, c)
}

var ErrBadCredentials = errors.New("bad credentials")