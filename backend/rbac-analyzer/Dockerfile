# Build stage
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/rbac-analyzer ./cmd/analyzer

# Runtime stage
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata helm
COPY --from=builder /bin/rbac-analyzer /usr/local/bin/rbac-analyzer

ENTRYPOINT ["rbac-analyzer"]
