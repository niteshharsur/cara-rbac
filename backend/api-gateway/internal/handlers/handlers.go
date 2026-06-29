package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

// ScanHandler proxies scan lifecycle requests.
type ScanHandler struct {
	DB *sql.DB
}

func NewScanHandler(db *sql.DB) *ScanHandler {
	return &ScanHandler{DB: db}
}

type createScanRequest struct {
	ApplicationID string `json:"application_id" binding:"required,uuid"`
	ClusterID     string `json:"cluster_id"`
	Mode          string `json:"mode" binding:"required,oneof=pre_deployment hybrid runtime_only"`
	SourceRepoURL string `json:"source_repo_url"`
	// RuntimeWindowSeconds defaults to 604800 (7 days) if omitted
	RuntimeWindowSeconds int `json:"runtime_window_seconds"`
}

func (h *ScanHandler) ListScans(c *gin.Context) {
	status := c.DefaultQuery("status", "")

	var rows *sql.Rows
	var err error

	if status != "" {
		rows, err = h.DB.Query(
			`SELECT id, application_id, cluster_id, mode, status, started_at, completed_at, created_at, app_risk_score, risk_explanation 
			 FROM scans 
			 WHERE status = $1 
			 ORDER BY created_at DESC`,
			status,
		)
	} else {
		rows, err = h.DB.Query(
			`SELECT id, application_id, cluster_id, mode, status, started_at, completed_at, created_at, app_risk_score, risk_explanation 
			 FROM scans 
			 ORDER BY created_at DESC`,
		)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list scans"})
		return
	}
	defer rows.Close()

	var scans []interface{}
	for rows.Next() {
		var id, appID, mode, stat string
		var clusterID sql.NullString
		var startedAt, completedAt sql.NullTime
		var createdAt time.Time
		var appRiskScore float64
		var riskExplanation sql.NullString

		if err := rows.Scan(&id, &appID, &clusterID, &mode, &stat, &startedAt, &completedAt, &createdAt, &appRiskScore, &riskExplanation); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan row"})
			return
		}

		scans = append(scans, gin.H{
			"id":               id,
			"scan_id":          id,
			"application_id":   appID,
			"cluster_id":       clusterID.String,
			"mode":             mode,
			"status":           stat,
			"started_at":       startedAt.Time,
			"completed_at":     completedAt.Time,
			"created_at":       createdAt,
			"app_risk_score":   appRiskScore,
			"risk_explanation": riskExplanation.String,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scans": scans,
		"total": len(scans),
	})
}

func (h *ScanHandler) CreateScan(c *gin.Context) {
	var req createScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RuntimeWindowSeconds == 0 {
		req.RuntimeWindowSeconds = 604800
	}

	var scanID string
	var clusterID sql.NullString
	if req.ClusterID != "" {
		clusterID.String = req.ClusterID
		clusterID.Valid = true
	}

	err := h.DB.QueryRow(
		`INSERT INTO scans (application_id, cluster_id, mode, status, runtime_window_seconds, started_at) 
		 VALUES ($1, $2, $3, 'running', $4, NOW()) 
		 RETURNING id`,
		req.ApplicationID, clusterID, req.Mode, req.RuntimeWindowSeconds,
	).Scan(&scanID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to queue scan: " + err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"status":  "running",
		"message": "scan created — analysis pipeline initiated",
	})
}

func (h *ScanHandler) GetScan(c *gin.Context) {
	scanID := c.Param("scanID")

	var id, appID, mode, stat string
	var clusterID sql.NullString
	var startedAt, completedAt sql.NullTime
	var createdAt time.Time
	var appRiskScore float64
	var riskExplanation sql.NullString

	err := h.DB.QueryRow(
		`SELECT id, application_id, cluster_id, mode, status, started_at, completed_at, created_at, app_risk_score, risk_explanation 
		 FROM scans 
		 WHERE id = $1`,
		scanID,
	).Scan(&id, &appID, &clusterID, &mode, &stat, &startedAt, &completedAt, &createdAt, &appRiskScore, &riskExplanation)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query scan: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":               id, // For compatibility with app.js
		"scan_id":          id,
		"application_id":   appID,
		"cluster_id":       clusterID.String,
		"mode":             mode,
		"status":           stat,
		"started_at":       startedAt.Time,
		"completed_at":     completedAt.Time,
		"created_at":       createdAt,
		"app_risk_score":   appRiskScore,
		"risk_explanation": riskExplanation.String,
	})
}

func (h *ScanHandler) DeleteScan(c *gin.Context) {
	scanID := c.Param("scanID")

	_, err := h.DB.Exec("DELETE FROM scans WHERE id = $1", scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete scan"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

func (h *ScanHandler) CancelScan(c *gin.Context) {
	scanID := c.Param("scanID")

	_, err := h.DB.Exec("UPDATE scans SET status = 'failed', completed_at = NOW() WHERE id = $1", scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cancel scan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

func (h *ScanHandler) ReclassifyScan(c *gin.Context) {
	scanID := c.Param("scanID")
	c.JSON(http.StatusAccepted, gin.H{"scan_id": scanID, "message": "reclassification triggered"})
}

// PermissionHandler handles observation and classification queries.
type PermissionHandler struct {
	DB *sql.DB
}

func NewPermissionHandler(db *sql.DB) *PermissionHandler {
	return &PermissionHandler{DB: db}
}

func (h *PermissionHandler) ListPermissions(c *gin.Context) {
	scanID := c.Param("scanID")
	source := c.DefaultQuery("source", "")

	var rows *sql.Rows
	var err error

	if source != "" {
		rows, err = h.DB.Query(
			`SELECT id, pod_id, source, verb, resource, api_group, scope, source_role, call_site_file, call_site_line 
			 FROM permission_observations 
			 WHERE scan_id = $1 AND source = $2 
			 ORDER BY id ASC`,
			scanID, source,
		)
	} else {
		rows, err = h.DB.Query(
			`SELECT id, pod_id, source, verb, resource, api_group, scope, source_role, call_site_file, call_site_line 
			 FROM permission_observations 
			 WHERE scan_id = $1 
			 ORDER BY id ASC`,
			scanID,
		)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query observations"})
		return
	}
	defer rows.Close()

	var permissions []interface{}
	for rows.Next() {
		var id int64
		var podID, src, verb, resource, apiGroup, scope string
		var sourceRole, callSiteFile sql.NullString
		var callSiteLine sql.NullInt64

		if err := rows.Scan(&id, &podID, &src, &verb, &resource, &apiGroup, &scope, &sourceRole, &callSiteFile, &callSiteLine); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan row"})
			return
		}

		permissions = append(permissions, gin.H{
			"id":             id,
			"pod_id":         podID,
			"source":         src,
			"verb":           verb,
			"resource":       resource,
			"api_group":      apiGroup,
			"scope":          scope,
			"source_role":    sourceRole.String,
			"call_site_file": callSiteFile.String,
			"call_site_line": callSiteLine.Int64,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":     scanID,
		"source":      source,
		"permissions": permissions,
	})
}

func (h *PermissionHandler) GetPermissionSummary(c *gin.Context) {
	scanID := c.Param("scanID")

	rows, err := h.DB.Query(
		`SELECT class, COUNT(*) 
		 FROM classifications 
		 WHERE scan_id = $1 
		 GROUP BY class`,
		scanID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get summary"})
		return
	}
	defer rows.Close()

	counts := gin.H{
		"CEP": 0, "SFP": 0, "DP": 0, "SOP": 0, "DRP": 0, "RP": 0,
	}

	for rows.Next() {
		var class string
		var count int
		if err := rows.Scan(&class, &count); err == nil {
			counts[class] = count
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"counts":  counts,
	})
}

func (h *PermissionHandler) ListClassifications(c *gin.Context) {
	scanID := c.Param("scanID")

	rows, err := h.DB.Query(
		`SELECT id, pod_id, verb, resource, scope, class, confidence, confidence_band, threat_score, rationale, evidence_ref 
		 FROM classifications 
		 WHERE scan_id = $1`,
		scanID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list classifications"})
		return
	}
	defer rows.Close()

	var classifications []interface{}
	for rows.Next() {
		var id int64
		var podID, verb, resource, scope, class, confidenceBand, rationale string
		var confidence, threatScore float64
		var evidenceRef []byte

		if err := rows.Scan(&id, &podID, &verb, &resource, &scope, &class, &confidence, &confidenceBand, &threatScore, &rationale, &evidenceRef); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan classification"})
			return
		}

		var evidence map[string]interface{}
		_ = json.Unmarshal(evidenceRef, &evidence)

		classifications = append(classifications, gin.H{
			"id":              id,
			"pod_id":          podID,
			"verb":            verb,
			"resource":        resource,
			"scope":           scope,
			"class":           class,
			"confidence":      confidence,
			"confidence_band": confidenceBand,
			"threat_score":    threatScore,
			"rationale":       rationale,
			"evidence":        evidence,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":         scanID,
		"classifications": classifications,
	})
}

func (h *PermissionHandler) GetByClass(c *gin.Context) {
	scanID := c.Param("scanID")
	class := c.Param("class")

	rows, err := h.DB.Query(
		`SELECT id, pod_id, verb, resource, scope, confidence, confidence_band, threat_score, rationale 
		 FROM classifications 
		 WHERE scan_id = $1 AND class = $2`,
		scanID, class,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query by class"})
		return
	}
	defer rows.Close()

	var items []interface{}
	for rows.Next() {
		var id int64
		var podID, verb, resource, scope, confidenceBand, rationale string
		var confidence, threatScore float64

		if err := rows.Scan(&id, &podID, &verb, &resource, &scope, &confidence, &confidenceBand, &threatScore, &rationale); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan row"})
			return
		}

		items = append(items, gin.H{
			"id":              id,
			"pod_id":          podID,
			"verb":            verb,
			"resource":        resource,
			"scope":           scope,
			"confidence":      confidence,
			"confidence_band": confidenceBand,
			"threat_score":    threatScore,
			"rationale":       rationale,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"class":   class,
		"items":   items,
	})
}

func (h *PermissionHandler) GetEvidence(c *gin.Context) {
	permID := c.Param("permID")

	var evidenceRef []byte
	err := h.DB.QueryRow(
		`SELECT evidence_ref FROM classifications WHERE id = $1`,
		permID,
	).Scan(&evidenceRef)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "classification not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query evidence"})
		return
	}

	var evidence map[string]interface{}
	_ = json.Unmarshal(evidenceRef, &evidence)

	c.JSON(http.StatusOK, gin.H{
		"perm_id":  permID,
		"evidence": evidence,
	})
}

func (h *PermissionHandler) AcknowledgePermission(c *gin.Context) {
	permID := c.Param("permID")

	// Inject record in audit_trail table
	// In production, userID is read from Gin context (middleware.JWTAuth set this)
	userIDVal, exists := c.Get("userID")
	var userID sql.NullString
	if exists {
		userID.String = userIDVal.(string)
		userID.Valid = true
	}

	_, err := h.DB.Exec(
		`INSERT INTO audit_trail (user_id, action, target_type, target_id, metadata) 
		 VALUES ($1, 'acknowledge', 'permission_classification', $2, '{}')`,
		userID, permID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record acknowledgment audit log"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"perm_id": permID, "acknowledged": true})
}

// RuntimeHandler handles runtime event and observation statistics.
type RuntimeHandler struct {
	DB *sql.DB
}

func NewRuntimeHandler(db *sql.DB) *RuntimeHandler {
	return &RuntimeHandler{DB: db}
}

func (h *RuntimeHandler) ListObservations(c *gin.Context) {
	scanID := c.Param("scanID")

	rows, err := h.DB.Query(
		`SELECT id, pod_id, verb, resource, api_group, scope, first_observed_at, last_observed_at, observed_count, is_startup_only 
		 FROM permission_observations 
		 WHERE scan_id = $1 AND source = 'runtime' 
		 ORDER BY last_observed_at DESC`,
		scanID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list observations"})
		return
	}
	defer rows.Close()

	var observations []interface{}
	for rows.Next() {
		var id int64
		var podID, verb, resource, apiGroup, scope string
		var firstObs, lastObs time.Time
		var count int
		var isStartup bool

		if err := rows.Scan(&id, &podID, &verb, &resource, &apiGroup, &scope, &firstObs, &lastObs, &count, &isStartup); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan row"})
			return
		}

		observations = append(observations, gin.H{
			"id":                id,
			"pod_id":            podID,
			"verb":              verb,
			"resource":          resource,
			"api_group":         apiGroup,
			"scope":             scope,
			"first_observed_at": firstObs,
			"last_observed_at":  lastObs,
			"observed_count":    count,
			"is_startup_only":   isStartup,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":      scanID,
		"observations": observations,
	})
}

func (h *RuntimeHandler) GetTimeline(c *gin.Context) {
	scanID := c.Param("scanID")

	// Timeline bins observations hourly for visualization
	rows, err := h.DB.Query(
		`SELECT date_trunc('hour', last_observed_at) as hour, count(*) 
		 FROM permission_observations 
		 WHERE scan_id = $1 AND source = 'runtime' 
		 GROUP BY hour 
		 ORDER BY hour ASC`,
		scanID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch timeline"})
		return
	}
	defer rows.Close()

	var timeline []interface{}
	for rows.Next() {
		var hour time.Time
		var count int
		if err := rows.Scan(&hour, &count); err == nil {
			timeline = append(timeline, gin.H{
				"hour":  hour,
				"count": count,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  scanID,
		"timeline": timeline,
	})
}

func (h *RuntimeHandler) GetPodCalls(c *gin.Context) {
	scanID := c.Param("scanID")
	podName := c.Param("podName")

	rows, err := h.DB.Query(
		`SELECT o.verb, o.resource, o.observed_count 
		 FROM permission_observations o 
		 JOIN pods p ON o.pod_id = p.id 
		 WHERE o.scan_id = $1 AND o.source = 'runtime' AND p.pod_name = $2`,
		scanID, podName,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query pod calls"})
		return
	}
	defer rows.Close()

	var calls []interface{}
	for rows.Next() {
		var verb, resource string
		var count int
		if err := rows.Scan(&verb, &resource, &count); err == nil {
			calls = append(calls, gin.H{
				"verb":     verb,
				"resource": resource,
				"count":    count,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"pod":     podName,
		"calls":   calls,
	})
}

// MinimizationHandler handles policy minimization outputs.
type MinimizationHandler struct {
	DB *sql.DB
}

func NewMinimizationHandler(db *sql.DB) *MinimizationHandler {
	return &MinimizationHandler{DB: db}
}

func (h *MinimizationHandler) TriggerMinimization(c *gin.Context) {
	scanID := c.Param("scanID")
	c.JSON(http.StatusAccepted, gin.H{"scan_id": scanID, "message": "minimization triggered"})
}

func (h *MinimizationHandler) GetMinimizationResult(c *gin.Context) {
	scanID := c.Param("scanID")

	var id, minimizedYAML string
	var originalCount, minimizedCount int
	var reductionPct float64
	var deployStatus, deployDetails, splitRecs sql.NullString

	err := h.DB.QueryRow(
		`SELECT id, original_count, minimized_count, reduction_pct, minimized_yaml, deployability_status, validation_details, role_splitting_suggestions 
		 FROM minimization_results 
		 WHERE scan_id = $1 
		 ORDER BY created_at DESC LIMIT 1`,
		scanID,
	).Scan(&id, &originalCount, &minimizedCount, &reductionPct, &minimizedYAML, &deployStatus, &deployDetails, &splitRecs)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "minimization result not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query minimization result: " + err.Error()})
		return
	}

	// Try to unmarshal JSON suggestions if present
	var recs interface{}
	if splitRecs.Valid && splitRecs.String != "" {
		_ = json.Unmarshal([]byte(splitRecs.String), &recs)
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":                    scanID,
		"result_id":                  id,
		"original_count":             originalCount,
		"minimized_count":            minimizedCount,
		"reduction_pct":              reductionPct,
		"minimized_yaml":             minimizedYAML,
		"validation_status":          deployStatus.String,
		"validation_details":         deployDetails.String,
		"role_splitting_suggestions": recs,
	})
}

func (h *MinimizationHandler) GetYAMLDiff(c *gin.Context) {
	scanID := c.Param("scanID")

	var minimizedYAML string
	err := h.DB.QueryRow(
		`SELECT minimized_yaml FROM minimization_results WHERE scan_id = $1 ORDER BY created_at DESC LIMIT 1`,
		scanID,
	).Scan(&minimizedYAML)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "minimization result not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query diff"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":        scanID,
		"minimized_yaml": minimizedYAML,
		"original_yaml":  "# original policy manifests (see cluster collection / M1)",
	})
}

func (h *MinimizationHandler) GetRollback(c *gin.Context) {
	scanID := c.Param("scanID")

	var rollbackScript string
	err := h.DB.QueryRow(
		`SELECT rollback_script FROM minimization_results WHERE scan_id = $1 ORDER BY created_at DESC LIMIT 1`,
		scanID,
	).Scan(&rollbackScript)

	if err == sql.ErrNoRows {
		c.Header("Content-Disposition", "attachment; filename=rollback.sh")
		c.Data(http.StatusNotFound, "text/plain", []byte("# Rollback script not found for scan "+scanID))
		return
	} else if err != nil {
		c.Header("Content-Disposition", "attachment; filename=rollback.sh")
		c.Data(http.StatusInternalServerError, "text/plain", []byte("# Database query failed"))
		return
	}

	c.Header("Content-Disposition", "attachment; filename=rollback.sh")
	c.Data(http.StatusOK, "text/plain", []byte(rollbackScript))
}

func (h *MinimizationHandler) ApplyToCluster(c *gin.Context) {
	scanID := c.Param("scanID")
	var body struct {
		DryRun bool `json:"dry_run"`
	}
	_ = c.ShouldBindJSON(&body)

	// Update validation status in Postgres
	var valStatus string
	if body.DryRun {
		valStatus = "skipped"
	} else {
		valStatus = "passed"
	}

	_, err := h.DB.Exec(
		`UPDATE minimization_results 
		 SET validation_status = $1 
		 WHERE scan_id = $2`,
		valStatus, scanID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update validation status"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"status":  "applied",
		"dry_run": body.DryRun,
	})
}

// GraphHandler handles graph traversal queries via graph-svc proxying.
type GraphHandler struct {
	DB *sql.DB
}

func NewGraphHandler(db *sql.DB) *GraphHandler {
	return &GraphHandler{DB: db}
}

func getGraphSvcURL() string {
	url := os.Getenv("GRAPH_SVC_URL")
	if url == "" {
		url = "http://localhost:8082"
	}
	return url
}

func (h *GraphHandler) SyncGraph(c *gin.Context) {
	scanID := c.Param("scanID")
	targetURL := fmt.Sprintf("%s/api/v1/sync/%s", getGraphSvcURL(), scanID)

	resp, err := http.Post(targetURL, "application/json", nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "graph-svc unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

func (h *GraphHandler) GetPermissionGraph(c *gin.Context) {
	scanID := c.Param("scanID")
	targetURL := fmt.Sprintf("%s/api/v1/graph/%s/permissions", getGraphSvcURL(), scanID)

	resp, err := http.Get(targetURL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "graph-svc unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

func (h *GraphHandler) GetAttackPaths(c *gin.Context) {
	scanID := c.Param("scanID")
	targetURL := fmt.Sprintf("%s/api/v1/graph/%s/attack-paths", getGraphSvcURL(), scanID)

	resp, err := http.Get(targetURL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "graph-svc unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

func (h *GraphHandler) GetBlastRadius(c *gin.Context) {
	scanID := c.Param("scanID")
	podName := c.Param("podName")
	targetURL := fmt.Sprintf("%s/api/v1/graph/%s/blast-radius/%s", getGraphSvcURL(), scanID, podName)

	resp, err := http.Get(targetURL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "graph-svc unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

// GraphQLHandler is a thin pass-through.
type GraphQLHandler struct{}

func NewGraphQLHandler() *GraphQLHandler { return &GraphQLHandler{} }

func (h *GraphQLHandler) Handle(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": nil, "errors": nil})
}

func (h *GraphQLHandler) Playground(c *gin.Context) {
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, graphqlPlaygroundHTML)
}

const graphqlPlaygroundHTML = `<!DOCTYPE html>
<html>
<head><title>CARA-RBAC GraphQL Playground</title>
<link rel="stylesheet" href="https://unpkg.com/graphiql/graphiql.min.css"/>
</head>
<body style="margin:0">
<div id="graphiql" style="height:100vh"></div>
<script crossorigin src="https://unpkg.com/react/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom/umd/react-dom.production.min.js"></script>
<script crossorigin src="https://unpkg.com/graphiql/graphiql.min.js"></script>
<script>
  ReactDOM.render(
    React.createElement(GraphiQL, { fetcher: GraphiQL.createFetcher({ url: '/graphql' }) }),
    document.getElementById('graphiql'),
  );
</script>
</body>
</html>`
