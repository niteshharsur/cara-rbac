# Build stage
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY backend/rbac-analyzer /src/rbac-analyzer
WORKDIR /src/cluster-collector
COPY backend/cluster-collector/go.mod backend/cluster-collector/go.sum ./
RUN go mod download
COPY backend/cluster-collector/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/cluster-collector ./cmd/collector

# Runtime stage
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/cluster-collector /usr/local/bin/cluster-collector

ENTRYPOINT ["cluster-collector"]
