# -------- Build Stage --------
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Required for CGO sqlite3
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /app/server ./cmd/server

# -------- Runtime Stage --------
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/server /app/server
COPY schema.sql ./schema.sql
COPY templates ./templates
COPY static ./static
RUN mkdir -p /app/data
ENV ADDR=":8080" SQLITE_DSN="file:/app/data/forum.db?_foreign_keys=on"
EXPOSE 8080
CMD ["/app/server"]
