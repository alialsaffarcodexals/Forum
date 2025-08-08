package internal

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"sync"
)

// Templater holds a parsed template set.
type Templater struct {
	mu *sync.RWMutex
	t  *template.Template
}

// NewTemplater parses all *.tmpl.html files in ./templates at startup.
func NewTemplater() (*Templater, error) {
	// Match all templates (including base)
	pattern := filepath.Join("templates", "*.tmpl.html")

	t, err := template.ParseGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %w", err)
	}

	return &Templater{
		mu: &sync.RWMutex{},
		t:  t,
	}, nil
}

// Render executes the base template, injecting the requested page template into it.
func (t *Templater) Render(w http.ResponseWriter, name string, data any, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	t.mu.RLock()
	defer t.mu.RUnlock()

	// Always execute base.tmpl.html, but set a variable telling it which page to include
	err := t.t.ExecuteTemplate(w, "base.tmpl.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
	}
}

// StaticFS serves files from ./static on disk (e.g., /static/style.css).
func StaticFS() http.Handler {
	return http.FileServer(http.Dir("static"))
}
