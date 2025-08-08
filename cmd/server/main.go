package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/forum/internal"
)

// LoggingMiddleware prints method, path, and duration for each request
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("Completed in %v", time.Since(start))
	})
}

func main() {
	fmt.Println("🚀 Server starting...")

	addr := getEnv("ADDR", ":8080")
	dsn := getEnv("SQLITE_DSN", "file:data/forum.db?_foreign_keys=on")

	db, err := internal.OpenDB(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := internal.ApplySchema(db, "schema.sql"); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	app := internal.NewApp(db)
	app.RegisterRoutes(mux)

	// Add logging + security headers + recovery
	handler := LoggingMiddleware(
		internal.WithRecover(
			internal.WithSecurityHeaders(mux),
		),
	)

	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
