# =========================
# STAGE 1 — BUILD
# =========================
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -o app


# =========================
# STAGE 2 — RUNTIME
# =========================
FROM alpine:3.19

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/app .

ENTRYPOINT ["./app"]
