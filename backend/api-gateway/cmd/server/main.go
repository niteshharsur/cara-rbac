package main

import (
	"database/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"cara-rbac/api-gateway/internal/middleware"
	"cara-rbac/api-gateway/internal/router"
	"cara-rbac/api-gateway/internal/ws"
)

func main() {
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	dbURL := os.Getenv("POSTGRES_URL")
	if dbURL == "" {
		dbURL = "postgresql://cara:cara_dev_secret@localhost:5432/cara_rbac?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Printf("warning: database ping failed: %v. Running without live db connection.", err)
	}

	r := gin.New()

	// Global middleware
	r.Use(gin.Recovery())
	r.Use(middleware.RequestLogger())
	r.Use(middleware.CORS())

	// Health check (unauthenticated)
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "api-gateway"})
	})

	// Auth routes (unauthenticated)
	auth := r.Group("/api/v1/auth")
	router.RegisterAuthRoutes(auth, db)

	// Protected API routes
	api := r.Group("/api/v1")
	api.Use(middleware.JWTAuth())
	api.Use(middleware.RateLimit())

	router.RegisterScanRoutes(api, db)
	router.RegisterPermissionRoutes(api, db)
	router.RegisterRuntimeRoutes(api, db)
	router.RegisterMinimizationRoutes(api, db)
	router.RegisterGraphRoutes(api, db)

	// GraphQL endpoint
	router.RegisterGraphQL(r)

	// WebSocket — live runtime events
	hub := ws.NewHub()
	go hub.Run()
	r.GET("/ws/events", middleware.JWTAuth(), func(c *gin.Context) {
		ws.ServeWS(hub, c.Writer, c.Request)
	})

	// Serve static files
	r.StaticFile("/style.css", "../../frontend/dashboard/style.css")
	r.StaticFile("/app.js", "../../frontend/dashboard/app.js")

	// NoRoute fallback for SPA routing
	r.NoRoute(func(c *gin.Context) {
		c.File("../../frontend/dashboard/index.html")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("CARA-RBAC API Gateway listening on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
