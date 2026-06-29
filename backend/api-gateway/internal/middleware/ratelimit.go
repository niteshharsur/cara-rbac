package middleware

import (
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// tokenBucket implements a simple per-IP token bucket rate limiter.
type tokenBucket struct {
	tokens    float64
	maxTokens float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func (tb *tokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens = min(tb.maxTokens, tb.tokens+elapsed*tb.refillRate)
	tb.lastRefill = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

type rateLimiter struct {
	buckets sync.Map // map[string]*tokenBucket
	max     float64
	rate    float64
}

func newRateLimiter(maxTokens, refillRate float64) *rateLimiter {
	rl := &rateLimiter{max: maxTokens, rate: refillRate}
	// Clean up stale buckets every 5 minutes
	go func() {
		for range time.Tick(5 * time.Minute) {
			rl.buckets.Range(func(k, v interface{}) bool {
				b := v.(*tokenBucket)
				b.mu.Lock()
				stale := time.Since(b.lastRefill) > 10*time.Minute
				b.mu.Unlock()
				if stale {
					rl.buckets.Delete(k)
				}
				return true
			})
		}
	}()
	return rl
}

func (rl *rateLimiter) getBucket(ip string) *tokenBucket {
	v, _ := rl.buckets.LoadOrStore(ip, &tokenBucket{
		tokens:    rl.max,
		maxTokens: rl.max,
		refillRate: rl.rate,
		lastRefill: time.Now(),
	})
	return v.(*tokenBucket)
}

var globalLimiter = func() *rateLimiter {
	max := 100.0
	rate := 10.0 // 10 req/s sustained
	if v, err := strconv.ParseFloat(os.Getenv("RATE_LIMIT_MAX"), 64); err == nil {
		max = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("RATE_LIMIT_RPS"), 64); err == nil {
		rate = v
	}
	return newRateLimiter(max, rate)
}()

// RateLimit is a per-IP token bucket rate limiter middleware.
func RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		bucket := globalLimiter.getBucket(ip)
		if !bucket.Allow() {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}
		c.Next()
	}
}
