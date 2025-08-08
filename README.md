# Go Forum (SQLite, Templates, No JS)

A simple forum that supports:
- User registration & login (email, username, password)
- Session cookies with UUID and expiration (1 week); one active session per user
- Create posts, assign categories (existing or new)
- Comments on posts
- Like/Dislike posts and comments
- Filter posts by category, your posts, or posts you liked
- SQLite storage; Dockerized

## Quick Start (local)

```bash
# prerequisites: Go 1.22, SQLite (optional), CGO toolchain
make # or go build ./cmd/server
./forum
# visit http://localhost:8080