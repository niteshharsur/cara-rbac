package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/lib/pq"
	"cara-rbac/rbac-analyzer/pkg/binding"
	"cara-rbac/rbac-analyzer/pkg/model"
	"cara-rbac/rbac-analyzer/pkg/parser"
	"cara-rbac/rbac-analyzer/pkg/wildcard"
)

func main() {
	var (
		inputPath  = flag.String("input", "", "Path to manifest directory or Helm chart root (required)")
		scanID     = flag.String("scan-id", "", "UUID of the parent scan record in Postgres (required)")
		outputJSON = flag.String("output", "", "If set, write P_req JSON to this file instead of Postgres")
		dbURL      = flag.String("db", os.Getenv("POSTGRES_URL"), "Postgres connection URL")
		valuesFile = flag.String("values", "", "Helm values override file (optional)")
		namespace  = flag.String("namespace", "default", "Kubernetes namespace for Helm overrides")
	)
	flag.Parse()

	if *inputPath == "" || *scanID == "" {
		flag.Usage()
		os.Exit(1)
	}

	log.Printf("[M1] starting RBAC analysis  scan=%s  input=%s", *scanID, *inputPath)

	// ── Step 1: Load manifest set ──────────────────────────────────────────────
	var ms *parser.ManifestSet
	var err error

	if parser.IsHelmChart(*inputPath) {
		log.Println("[M1] detected Helm chart — rendering with `helm template`")
		renderer := parser.NewHelmRenderer()
		valuesFiles := []string{}
		if *valuesFile != "" {
			valuesFiles = append(valuesFiles, *valuesFile)
		}
		ms, err = renderer.RenderUmbrellaChart(*inputPath, "cara-scan", *namespace, valuesFiles)
	} else {
		log.Printf("[M1] loading plain YAML manifests from %s", *inputPath)
		ms, err = parser.LoadManifestSet(*inputPath)
	}
	if err != nil {
		log.Fatalf("[M1] manifest load failed: %v", err)
	}

	pods := ms.ExtractPods()
	roles := ms.ExtractRoles()
	clusterRoles := ms.ExtractClusterRoles()
	roleBindings, clusterBindings := ms.ExtractBindings()

	log.Printf("[M1] found  pods=%d  roles=%d  clusterRoles=%d  roleBindings=%d  clusterBindings=%d",
		len(pods), len(roles), len(clusterRoles), len(roleBindings), len(clusterBindings))

	// ── Step 2: Build binding resolver ────────────────────────────────────────
	resolver := binding.NewResolver(roles, clusterRoles, roleBindings, clusterBindings)

	// ── Step 3: Resolve + expand for each pod → P_req ─────────────────────────
	results := make(model.PermissionSetMap, len(pods))

	for _, pod := range pods {
		resolvedRoles := resolver.ResolveForPod(pod)
		tuples := wildcard.ExpandAll(resolvedRoles)

		key := pod.Namespace + "/" + pod.Name
		results[key] = model.PodPermissionSet{
			PodName:        pod.Name,
			Namespace:      pod.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
			Tuples:         tuples,
		}

		log.Printf("[M1]   pod=%-40s  sa=%-20s  permissions=%d",
			key, pod.Spec.ServiceAccountName, len(tuples))
	}

	// ── Step 4: Persist or write to file ──────────────────────────────────────
	if *outputJSON != "" {
		if err := writeJSON(*outputJSON, results); err != nil {
			log.Fatalf("[M1] JSON write failed: %v", err)
		}
		log.Printf("[M1] P_req written to %s", *outputJSON)
		return
	}

	if *dbURL == "" {
		log.Fatal("[M1] --db or POSTGRES_URL required when --output is not set")
	}

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("[M1] db open failed: %v", err)
	}
	defer db.Close()

	if err := persistToDB(db, *scanID, results); err != nil {
		log.Fatalf("[M1] db persist failed: %v", err)
	}

	log.Printf("[M1] P_req persisted  scan=%s  pods=%d", *scanID, len(results))
}

// persistToDB writes P_req tuples to the permission_observations table.
func persistToDB(db *sql.DB, scanID string, results model.PermissionSetMap) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Upsert each pod record first, then insert observations
	podStmt, err := tx.Prepare(`
		INSERT INTO pods (scan_id, pod_name, namespace, service_account)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (scan_id, pod_name, namespace) DO UPDATE
		  SET service_account = EXCLUDED.service_account
		RETURNING id
	`)
	if err != nil {
		return fmt.Errorf("prepare pod stmt: %w", err)
	}
	defer podStmt.Close()

	obsStmt, err := tx.Prepare(`
		INSERT INTO permission_observations
		  (scan_id, pod_id, source, verb, resource, api_group, scope, resource_names, source_role)
		VALUES ($1, $2, 'requested', $3, $4, $5, $6, $7, $8)
	`)
	if err != nil {
		return fmt.Errorf("prepare obs stmt: %w", err)
	}
	defer obsStmt.Close()

	for _, pps := range results {
		var podID string
		err := podStmt.QueryRow(scanID, pps.PodName, pps.Namespace, pps.ServiceAccount).Scan(&podID)
		if err != nil {
			return fmt.Errorf("upsert pod %s/%s: %w", pps.Namespace, pps.PodName, err)
		}

		for _, t := range pps.Tuples {
			_, err := obsStmt.Exec(
				scanID, podID,
				t.Verb, t.Resource, t.APIGroup, string(t.Scope),
				sliceToArray(t.ResourceNames),
				t.SourceRole,
			)
			if err != nil {
				return fmt.Errorf("insert observation: %w", err)
			}
		}
	}

	return tx.Commit()
}

// writeJSON serialises results to a JSON file (useful for local testing).
func writeJSON(path string, results model.PermissionSetMap) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// sliceToArray converts a Go string slice to a PostgreSQL text[] literal.
func sliceToArray(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}
