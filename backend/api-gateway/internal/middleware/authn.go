
package middleware

import (
	"crypto/rsa"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtPublicKey  *rsa.PublicKey
	jwtPrivateKey *rsa.PrivateKey
)

func init() {
	// Load RSA keys from env-specified paths (PEM files)
	pubPath := os.Getenv("JWT_PUBLIC_KEY_PATH")
	privPath := os.Getenv("JWT_SIGNING_KEY_PATH")

	if pubPath != "" {
		data, err := os.ReadFile(pubPath)
		if err == nil {
			jwtPublicKey, _ = jwt.ParseRSAPublicKeyFromPEM(data)
		}
	}
	if privPath != "" {
		data, err := os.ReadFile(privPath)
		if err == nil {
			jwtPrivateKey, _ = jwt.ParseRSAPrivateKeyFromPEM(data)
		}
	}

	// Fall back to HS256 dev secret if no RSA keys are configured
	if jwtPublicKey == nil {
		devSecret := os.Getenv("JWT_DEV_SECRET")
		if devSecret == "" {
			devSecret = "cara-rbac-dev-secret-change-in-production"
		}
		_ = devSecret // used in hmacKeyFunc below
	}
}

// CARAClaims extends RegisteredClaims with CARA-RBAC specific fields.
type CARAClaims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Role   string `json:"role"` // admin | engineer | viewer
	jwt.RegisteredClaims
}

// JWTAuth validates the Bearer token and injects userID/role into the Gin context.
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or malformed Authorization header",
			})
			return
		}

		tokenStr := strings.TrimPrefix(header, "Bearer ")
		claims := &CARAClaims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		// Inject into context — downstream handlers use these
		c.Set("userID", claims.UserID)
		c.Set("userEmail", claims.Email)
		c.Set("userRole", claims.Role)
		c.Next()
	}
}

// keyFunc selects the verification key based on the token's algorithm.
func keyFunc(t *jwt.Token) (interface{}, error) {
	switch t.Method.(type) {
	case *jwt.SigningMethodRSA:
		if jwtPublicKey == nil {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return jwtPublicKey, nil
	case *jwt.SigningMethodHMAC:
		secret := os.Getenv("JWT_DEV_SECRET")
		if secret == "" {
			secret = "cara-rbac-dev-secret-change-in-production"
		}
		return []byte(secret), nil
	default:
		return nil, jwt.ErrTokenSignatureInvalid
	}
}

// GetPrivateKey returns the loaded RSA private key (used by auth handler to issue tokens).
func GetPrivateKey() *rsa.PrivateKey { return jwtPrivateKey }

// RequireRole is a middleware that enforces a minimum role level.
// Role hierarchy: viewer < engineer < admin
func RequireRole(minRole string) gin.HandlerFunc {
	hierarchy := map[string]int{"viewer": 0, "engineer": 1, "admin": 2}
	return func(c *gin.Context) {
		role, _ := c.Get("userRole")
		roleStr, _ := role.(string)
		if hierarchy[roleStr] < hierarchy[minRole] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "insufficient permissions",
				"required": minRole,
			})
			return
		}
		c.Next()
	}
}
