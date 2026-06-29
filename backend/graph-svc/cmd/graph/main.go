package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func main() {
	var (
		port     = flag.String("port", "8082", "HTTP server port")
		dbURL    = flag.String("db", os.Getenv("POSTGRES_URL"), "Postgres connection URL")
		neo4jURI = flag.String("neo4j-uri", os.Getenv("NEO4J_URI"), "Neo4j bolt URI")
		neo4jUser = flag.String("neo4j-user", "neo4j", "Neo4j username")
		neo4jPass = flag.String("neo4j-pass", os.Getenv("NEO4J_PASSWORD"), "Neo4j password")
	)
	flag.Parse()

	if *dbURL == "" {
		*dbURL = "postgresql://cara:cara_dev_secret@localhost:5432/cara_rbac?sslmode=disable"
	}
	if *neo4jURI == "" {
		*neo4jURI = "bolt://localhost:7687"
	}
	if *neo4jPass == "" {
		*neo4jPass = "cara_dev_secret"
	}

	// ── Postgres connection ──────────────────────────────────────────────────
	pgDB, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("[graph-svc] postgres open failed: %v", err)
	}
	defer pgDB.Close()

	// ── Neo4j connection ─────────────────────────────────────────────────────
	driver, err := neo4j.NewDriverWithContext(*neo4jURI,
		neo4j.BasicAuth(*neo4jUser, *neo4jPass, ""))
	if err != nil {
		log.Fatalf("[graph-svc] neo4j driver failed: %v", err)
	}
	defer driver.Close(context.Background())

	// Verify Neo4j connectivity
	ctx := context.Background()
	if err := driver.VerifyConnectivity(ctx); err != nil {
		log.Printf("[graph-svc] warning: neo4j connectivity check failed: %v", err)
	} else {
		log.Println("[graph-svc] neo4j connected")
	}

	svc := &GraphService{pgDB: pgDB, neo4j: driver}

	// ── HTTP server ──────────────────────────────────────────────────────────
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "graph-svc"})
	})

	api := r.Group("/api/v1")
	api.POST("/sync/:scanID", svc.SyncToNeo4j)
	api.GET("/graph/:scanID/permissions", svc.GetPermissionGraph)
	api.GET("/graph/:scanID/attack-paths", svc.GetAttackPaths)
	api.GET("/graph/:scanID/blast-radius/:podName", svc.GetBlastRadius)

	log.Printf("[graph-svc] listening on :%s", *port)
	if err := r.Run(":" + *port); err != nil {
		log.Fatalf("[graph-svc] server error: %v", err)
	}
}

type GraphService struct {
	pgDB  *sql.DB
	neo4j neo4j.DriverWithContext
}

// SyncToNeo4j reads permission data from Postgres and syncs it to Neo4j as a graph.
func (s *GraphService) SyncToNeo4j(c *gin.Context) {
	scanID := c.Param("scanID")
	ctx := c.Request.Context()

	// Step 1: Load pods
	podRows, err := s.pgDB.Query(
		`SELECT id, pod_name, namespace, service_account FROM pods WHERE scan_id = $1`, scanID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load pods: " + err.Error()})
		return
	}
	defer podRows.Close()

	session := s.neo4j.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	// Clear existing scan data in Neo4j
	_, err = session.Run(ctx, "MATCH (n {scan_id: $scanID}) DETACH DELETE n", map[string]any{"scanID": scanID})
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to clear neo4j: " + err.Error()})
		return
	}

	podCount := 0
	for podRows.Next() {
		var id, podName, ns, sa string
		if err := podRows.Scan(&id, &podName, &ns, &sa); err != nil {
			continue
		}

		// Create Pod node
		_, err = session.Run(ctx,
			`CREATE (p:Pod {id: $id, name: $name, namespace: $ns, service_account: $sa, scan_id: $scanID})`,
			map[string]any{"id": id, "name": podName, "ns": ns, "sa": sa, "scanID": scanID})
		if err != nil {
			log.Printf("[graph-svc] failed to create pod node: %v", err)
		}

		// Create ServiceAccount node and relationship
		_, _ = session.Run(ctx,
			`MERGE (sa:ServiceAccount {name: $sa, namespace: $ns, scan_id: $scanID})
			 WITH sa
			 MATCH (p:Pod {id: $id, scan_id: $scanID})
			 CREATE (p)-[:USES_SA]->(sa)`,
			map[string]any{"id": id, "sa": sa, "ns": ns, "scanID": scanID})

		podCount++
	}

	// Step 2: Load permission observations and create Permission nodes + edges
	obsRows, err := s.pgDB.Query(
		`SELECT pod_id, source, verb, resource, api_group, scope
		 FROM permission_observations WHERE scan_id = $1`, scanID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to load observations: " + err.Error()})
		return
	}
	defer obsRows.Close()

	permCount := 0
	for obsRows.Next() {
		var podID, source, verb, resource, apiGroup, scope string
		if err := obsRows.Scan(&podID, &source, &verb, &resource, &apiGroup, &scope); err != nil {
			continue
		}

		// Create Permission node and relationship
		_, err = session.Run(ctx,
			`MERGE (perm:Permission {verb: $verb, resource: $resource, api_group: $apiGroup, scope: $scope, scan_id: $scanID})
			 WITH perm
			 MATCH (p:Pod {id: $podID, scan_id: $scanID})
			 CREATE (p)-[:HAS_PERMISSION {source: $source}]->(perm)`,
			map[string]any{
				"podID": podID, "verb": verb, "resource": resource,
				"apiGroup": apiGroup, "scope": scope, "source": source, "scanID": scanID,
			})
		if err != nil {
			log.Printf("[graph-svc] failed to create perm edge: %v", err)
		}
		permCount++
	}

	// Step 3: Load classifications and add labels
	classRows, err := s.pgDB.Query(
		`SELECT pod_id, verb, resource, class, threat_score
		 FROM classifications WHERE scan_id = $1`, scanID)
	if err == nil {
		defer classRows.Close()
		for classRows.Next() {
			var podID, verb, resource, class string
			var threatScore float64
			if err := classRows.Scan(&podID, &verb, &resource, &class, &threatScore); err == nil {
				_, _ = session.Run(ctx,
					`MATCH (p:Pod {id: $podID, scan_id: $scanID})-[r:HAS_PERMISSION]->(perm:Permission {verb: $verb, resource: $resource, scan_id: $scanID})
					 SET r.class = $class, r.threat_score = $threat`,
					map[string]any{
						"podID": podID, "verb": verb, "resource": resource,
						"class": class, "threat": threatScore, "scanID": scanID,
					})
			}
		}
	}

	c.JSON(200, gin.H{
		"scan_id":    scanID,
		"pods":       podCount,
		"permissions": permCount,
		"message":    "sync complete",
	})
}

// GetPermissionGraph returns the D3-compatible nodes and edges.
func (s *GraphService) GetPermissionGraph(c *gin.Context) {
	scanID := c.Param("scanID")
	ctx := c.Request.Context()

	session := s.neo4j.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	// Get all nodes
	result, err := session.Run(ctx,
		`MATCH (n {scan_id: $scanID}) RETURN labels(n) AS labels, properties(n) AS props`,
		map[string]any{"scanID": scanID})
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query nodes"})
		return
	}

	var nodes []gin.H
	for result.Next(ctx) {
		record := result.Record()
		labels, _ := record.Get("labels")
		props, _ := record.Get("props")
		nodes = append(nodes, gin.H{
			"labels": labels,
			"data":   props,
		})
	}

	// Get all relationships
	relResult, err := session.Run(ctx,
		`MATCH (a {scan_id: $scanID})-[r]->(b {scan_id: $scanID})
		 RETURN coalesce(a.id, a.name) AS source, 
		        type(r) AS rel_type, 
		        properties(r) AS rel_props, 
		        CASE WHEN 'Permission' IN labels(b) THEN b.verb + ':' + b.resource ELSE coalesce(b.id, b.name) END AS target`,
		map[string]any{"scanID": scanID})

	var edges []gin.H
	if err == nil {
		for relResult.Next(ctx) {
			record := relResult.Record()
			source, _ := record.Get("source")
			relType, _ := record.Get("rel_type")
			relProps, _ := record.Get("rel_props")
			target, _ := record.Get("target")
			edges = append(edges, gin.H{
				"source":     source,
				"target":     target,
				"type":       relType,
				"properties": relProps,
			})
		}
	}

	c.JSON(200, gin.H{
		"scan_id": scanID,
		"nodes":   nodes,
		"edges":   edges,
	})
}

// GetAttackPaths finds escalation paths through the permission graph.
func (s *GraphService) GetAttackPaths(c *gin.Context) {
	scanID := c.Param("scanID")
	ctx := c.Request.Context()

	session := s.neo4j.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	// Find pods with CEP-class permissions to sensitive resources
	result, err := session.Run(ctx,
		`MATCH path = (p:Pod {scan_id: $scanID})-[r:HAS_PERMISSION]->(perm:Permission {scan_id: $scanID})
		 WHERE r.class = 'CEP' AND perm.resource IN ['secrets', 'pods', 'roles', 'clusterroles', 'clusterrolebindings']
		 RETURN p.name AS pod_name, p.namespace AS namespace, 
		        perm.verb AS verb, perm.resource AS resource, perm.scope AS scope,
		        r.threat_score AS threat_score
		 ORDER BY r.threat_score DESC`,
		map[string]any{"scanID": scanID})

	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query attack paths"})
		return
	}

	var paths []gin.H
	for result.Next(ctx) {
		record := result.Record()
		podName, _ := record.Get("pod_name")
		ns, _ := record.Get("namespace")
		verb, _ := record.Get("verb")
		resource, _ := record.Get("resource")
		scope, _ := record.Get("scope")
		threat, _ := record.Get("threat_score")

		paths = append(paths, gin.H{
			"pod":          podName,
			"namespace":    ns,
			"verb":         verb,
			"resource":     resource,
			"scope":        scope,
			"threat_score": threat,
			"impact":       deriveImpact(resource, verb),
		})
	}

	c.JSON(200, gin.H{
		"scan_id":      scanID,
		"attack_paths": paths,
	})
}

// GetBlastRadius estimates the impact of a compromised pod.
func (s *GraphService) GetBlastRadius(c *gin.Context) {
	scanID := c.Param("scanID")
	podName := c.Param("podName")
	ctx := c.Request.Context()

	session := s.neo4j.NewSession(ctx, neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close(ctx)

	// Count all permissions the pod has, grouped by class
	result, err := session.Run(ctx,
		`MATCH (p:Pod {name: $podName, scan_id: $scanID})-[r:HAS_PERMISSION]->(perm:Permission)
		 RETURN r.class AS class, count(*) AS cnt, collect(perm.verb + ':' + perm.resource) AS perms
		 ORDER BY cnt DESC`,
		map[string]any{"scanID": scanID, "podName": podName})

	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query blast radius"})
		return
	}

	var breakdown []gin.H
	totalExcess := 0
	for result.Next(ctx) {
		record := result.Record()
		class, _ := record.Get("class")
		cnt, _ := record.Get("cnt")
		perms, _ := record.Get("perms")

		classStr, _ := class.(string)
		cntInt, _ := cnt.(int64)

		if classStr == "CEP" {
			totalExcess = int(cntInt)
		}

		breakdown = append(breakdown, gin.H{
			"class":       class,
			"count":       cnt,
			"permissions": perms,
		})
	}

	rating := "LOW"
	if totalExcess > 20 {
		rating = "CRITICAL"
	} else if totalExcess > 10 {
		rating = "HIGH"
	} else if totalExcess > 3 {
		rating = "MEDIUM"
	}

	c.JSON(200, gin.H{
		"scan_id":            scanID,
		"pod":                podName,
		"blast_radius_rating": rating,
		"excess_permissions":  totalExcess,
		"breakdown":          breakdown,
	})
}

func deriveImpact(resource, verb interface{}) string {
	r, _ := resource.(string)
	v, _ := verb.(string)

	switch {
	case r == "secrets" && (v == "get" || v == "list"):
		return "Secret exfiltration — attacker can read all secrets in scope"
	case r == "secrets" && (v == "create" || v == "update" || v == "patch"):
		return "Secret injection — attacker can plant malicious secrets"
	case r == "pods" && v == "create":
		return "Pod creation — attacker can spawn privileged containers"
	case r == "roles" || r == "clusterroles":
		return "Privilege escalation — attacker can create or modify RBAC roles"
	case r == "clusterrolebindings":
		return "Cluster-wide privilege escalation via binding modification"
	default:
		return "Excess permission — unnecessary access to " + r
	}
}
