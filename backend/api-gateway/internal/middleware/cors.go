package middleware

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that sets CORS headers.
// Allowed origins are read from CORS_ALLOWED_ORIGINS env var (comma-separated).
func CORS() gin.HandlerFunc {
	rawOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if rawOrigins == "" {
		rawOrigins = "http://localhost:5173,http://localhost:3000"
	}
	allowed := strings.Split(rawOrigins, ",")
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		allowedSet[strings.TrimSpace(o)] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if _, ok := allowedSet[origin]; ok {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Request-ID")
		c.Header("Access-Control-Max-Age", "86400")
		c.Header("Vary", "Origin")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// RequestLogger logs each request with latency and status code.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method

		if status >= 500 {
			gin.DefaultErrorWriter.Write([]byte(
				formatLog("ERROR", method, path, status, latency),
			))
		} else {
			gin.DefaultWriter.Write([]byte(
				formatLog("INFO", method, path, status, latency),
			))
		}
	}
}

func formatLog(level, method, path string, status int, latency time.Duration) string {
	return time.Now().Format(time.RFC3339) + " [" + level + "] " +
		method + " " + path + " " +
		http.StatusText(status) + " (" + latency.String() + ")\n"
}
