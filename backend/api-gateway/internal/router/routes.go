package router

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"cara-rbac/api-gateway/internal/handlers"
	"cara-rbac/api-gateway/internal/middleware"
)

// RegisterScanRoutes mounts all /scans endpoints.
func RegisterScanRoutes(rg *gin.RouterGroup, db *sql.DB) {
	h := handlers.NewScanHandler(db)
	scans := rg.Group("/scans")
	{
		scans.GET("", h.ListScans)
		scans.POST("", middleware.RequireRole("engineer"), h.CreateScan)
		scans.GET("/:scanID", h.GetScan)
		scans.DELETE("/:scanID", middleware.RequireRole("admin"), h.DeleteScan)
		scans.POST("/:scanID/cancel", middleware.RequireRole("engineer"), h.CancelScan)
		// Trigger re-classification without a full rescan
		scans.POST("/:scanID/reclassify", middleware.RequireRole("engineer"), h.ReclassifyScan)
	}
}

// RegisterPermissionRoutes mounts permission observation and classification endpoints.
func RegisterPermissionRoutes(rg *gin.RouterGroup, db *sql.DB) {
	h := handlers.NewPermissionHandler(db)
	perms := rg.Group("/scans/:scanID/permissions")
	{
		// Permission observations by source
		perms.GET("", h.ListPermissions)             // ?source=requested|static|runtime|cluster
		perms.GET("/summary", h.GetPermissionSummary) // counts per class
		// Classifications
		perms.GET("/classifications", h.ListClassifications)
		perms.GET("/classifications/:class", h.GetByClass) // class=CEP|DP|SOP|DRP|RP|SFP
		// Evidence for a single permission tuple
		perms.GET("/:permID/evidence", h.GetEvidence)
		// Acknowledge a classification (adds to audit trail)
		perms.POST("/:permID/acknowledge", middleware.RequireRole("engineer"), h.AcknowledgePermission)
	}
}

// RegisterRuntimeRoutes mounts runtime observation endpoints.
func RegisterRuntimeRoutes(rg *gin.RouterGroup, db *sql.DB) {
	h := handlers.NewRuntimeHandler(db)
	rt := rg.Group("/scans/:scanID/runtime")
	{
		rt.GET("/observations", h.ListObservations)    // paginated runtime events
		rt.GET("/timeline", h.GetTimeline)             // aggregated call timeline for Grafana
		rt.GET("/pods/:podName/calls", h.GetPodCalls)  // per-pod API call breakdown
	}
}

// RegisterMinimizationRoutes mounts RBAC minimization endpoints.
func RegisterMinimizationRoutes(rg *gin.RouterGroup, db *sql.DB) {
	h := handlers.NewMinimizationHandler(db)
	min := rg.Group("/scans/:scanID/minimization")
	{
		min.POST("", middleware.RequireRole("engineer"), h.TriggerMinimization)
		min.GET("", h.GetMinimizationResult)
		min.GET("/diff", h.GetYAMLDiff)        // original vs minimized YAML
		min.GET("/rollback", h.GetRollback)    // rollback script download
		min.POST("/apply", middleware.RequireRole("admin"), h.ApplyToCluster) // dry-run or live
	}
}

// RegisterGraphRoutes mounts permission graph and attack path endpoints.
func RegisterGraphRoutes(rg *gin.RouterGroup, db *sql.DB) {
	h := handlers.NewGraphHandler(db)
	graphs := rg.Group("/scans/:scanID/graph")
	{
		graphs.POST("/sync", middleware.RequireRole("engineer"), h.SyncGraph)
		graphs.GET("/permissions", h.GetPermissionGraph) // nodes + edges for D3
		graphs.GET("/attack-paths", h.GetAttackPaths)    // severity-ranked attack chains
		graphs.GET("/pods/:podName/blast-radius", h.GetBlastRadius)
	}
}

// RegisterGraphQL mounts the GraphQL endpoint (POST /graphql).
// The handler is a thin pass-through to graph-svc.
func RegisterGraphQL(r *gin.Engine) {
	h := handlers.NewGraphQLHandler()
	r.POST("/graphql", middleware.JWTAuth(), h.Handle)
	r.GET("/graphql", middleware.JWTAuth(), h.Playground) // GraphQL playground in dev
}
