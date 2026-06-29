FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ebpf-agent cmd/agent/main.go

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/ebpf-agent .
ENTRYPOINT ["./ebpf-agent"]
