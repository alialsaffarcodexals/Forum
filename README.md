# Forum

You are tasked with generating a full-stack community forum project called “ForumX.” Use Go for the backend and vanilla HTML/CSS (no JavaScript) for the frontend. The project should include:

1. Database schema (SQLite):
   - `users` table (id, email, password_hash, created_at)
   - `sessions` table (id UUID, user_id FK, expires_at)
   - `posts` table (id, user_id FK, title, content, created_at)
   - `post_categories` table (post_id FK, category)
   - `likes` table (id, user_id FK, post_id FK, is_like, created_at)
   - `comments` table (id, user_id FK, post_id FK, content, created_at)

2. A `schema.sql` file with `PRAGMA foreign_keys = ON;` and all CREATE TABLE statements, including appropriate FOREIGN KEY constraints and composite primary keys.

3. A Go module with:
   - `main.go` that:
     • Opens `forumx.db` using `github.com/mattn/go-sqlite3`  
     • Ensures `PRAGMA foreign_keys = ON;`  
     • Parses templates (one `index.html`) with `html/template`  
     • Exposes routes:
       - `GET  /`              → serve `index.html` with server-side data  
       - `POST /login`         → form-POST handler, reads form values `email`, `password`, verifies against bcrypt hash (`golang.org/x/crypto/bcrypt`), issues a session UUID (via `github.com/google/uuid`), stores in `sessions`, sets HTTP-only session cookie
       - `POST /posts`         → protected by session cookie, reads `title`, `content`, `categories`, inserts into `posts` and `post_categories`
       - `GET  /posts`         → reads optional query params `filter`, `mine`, `liked`, returns rendered list of posts
       - (Bonus: you may stub out `/about`, `/terms`, `/privacy`, `/forgot`, `/register` as static)
     • Middleware function to check and refresh sessions
     • Helper functions to load user info and posts with likes/dislikes counts
     • Proper HTTP status codes and JSON error responses only for non‐form endpoints

4. One single template file `index.html` that:
   - Uses Go template directives to loop over `.Posts` (with fields Title, AuthorEmail, CreatedAt, Categories, Content, Likes, Dislikes)
   - Implements a navbar with centered Home/About links and a right-side “Login” button
   - Implements a theme toggle (light/dark) using the CSS checkbox hack only
   - Implements a login modal using the CSS checkbox hack—hidden by default, toggled via `<label for="login-toggle">` and `<input type="checkbox" id="login-toggle">`
   - Implements a “Create New Post” card with an HTML `<form method="POST" action="/posts">`, fields for title, multiple checkboxes for categories (General, Tech, News, Fun), content textarea, submit button
   - Implements a two-column responsive grid (`@media (max-width:768px)` to one column), with a sidebar of filter links (e.g. `/?filter=Tech`, `/?mine=true`, `/?liked=true`) and a main section rendering `.Posts`
   - Footer with About/Terms/Privacy links

5. All CSS in a `<style>` block in `index.html`, using CSS variables for theme colors (`:root { --bg: #fff; --fg: #000; }`, `[data-theme="dark"] { … }`), and no external CSS or JS.

6. A Go helper to set the template’s `.Theme` field based on a cookie or default.

Generate **all** files needed:
- `schema.sql`
- `main.go`
- `index.html`

Do not include any Node.js, React, or client-side JavaScript. Keep all interactivity (theme toggle, modal) purely in HTML/CSS. Please output each file in full, with correct imports, package declarations, and Go module (`go.mod`) if necessary.
