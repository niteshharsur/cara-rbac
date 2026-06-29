package router

import (
	"database/sql"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"cara-rbac/api-gateway/internal/middleware"
)

type AuthRouter struct {
	DB *sql.DB
}

// RegisterAuthRoutes mounts register, login and token-refresh endpoints.
func RegisterAuthRoutes(rg *gin.RouterGroup, db *sql.DB) {
	ar := &AuthRouter{DB: db}
	rg.POST("/register", ar.handleRegister)
	rg.POST("/login", ar.handleLogin)
	rg.POST("/refresh", ar.handleRefresh)
}

type registerRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role" binding:"required,oneof=admin engineer viewer"`
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// handleRegister creates a new user in the database
func (ar *AuthRouter) handleRegister(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to secure password"})
		return
	}

	var userID string
	err = ar.DB.QueryRow(
		`INSERT INTO users (email, password_hash, role) 
		 VALUES ($1, $2, $3) 
		 RETURNING id`,
		req.Email, string(hashedPassword), req.Role,
	).Scan(&userID)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "unique constraint") || strings.Contains(errStr, "duplicate key") {
			c.JSON(http.StatusConflict, gin.H{"error": "user with this email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user_id": userID,
		"email":   req.Email,
		"role":    req.Role,
		"message": "user registered successfully",
	})
}

// handleLogin validates credentials and returns access + refresh tokens.
func (ar *AuthRouter) handleLogin(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var userID, passwordHash, role string
	err := ar.DB.QueryRow(
		`SELECT id, password_hash, role FROM users WHERE email = $1`,
		req.Email,
	).Scan(&userID, &passwordHash, &role)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	access, refresh, err := issueTokenPair(userID, req.Email, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":         access, // For compatibility with app.js
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    900, // 15 minutes
		"role":          role,   // User role mapping
	})
}

// handleRefresh validates the refresh token and issues a new access token.
func (ar *AuthRouter) handleRefresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims := &middleware.CARAClaims{}
	secret := os.Getenv("JWT_DEV_SECRET")
	if secret == "" {
		secret = "cara-rbac-dev-secret-change-in-production"
	}

	token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	access, _, err := issueTokenPair(claims.UserID, claims.Email, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   900,
	})
}

// issueTokenPair creates an access token (15 min) and refresh token (7 days).
func issueTokenPair(userID, email, role string) (string, string, error) {
	secret := os.Getenv("JWT_DEV_SECRET")
	if secret == "" {
		secret = "cara-rbac-dev-secret-change-in-production"
	}
	key := []byte(secret)

	now := time.Now()

	accessClaims := middleware.CARAClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			Issuer:    "cara-rbac",
		},
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(key)
	if err != nil {
		return "", "", err
	}

	refreshClaims := middleware.CARAClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(7 * 24 * time.Hour)),
			Issuer:    "cara-rbac",
		},
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(key)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
