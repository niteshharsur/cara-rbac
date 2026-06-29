package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"cara-rbac/runtime-monitor/falco"
)

// EventRequest represents a runtime Kubernetes API access event reported by agents
type EventRequest struct {
	ScanID    string `json:"scan_id"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Resource  string `json:"resource"`
	APIGroup  string `json:"api_group"`
	IsStartup bool   `json:"is_startup"`
}

// PodCache entry to avoid querying the DB for every single event
type PodCacheEntry struct {
	ID        string
	CreatedAt time.Time
}

var (
	podCache = make(map[string]PodCacheEntry) // Key: "scan_id/namespace/pod_name_prefix"
	cacheMu  sync.RWMutex
)

// List of known cluster-scoped resources
var clusterScopedResources = map[string]bool{
	"nodes":                            true,
	"namespaces":                       true,
	"persistentvolumes":                true,
	"clusterroles":                     true,
	"clusterrolebindings":              true,
	"certificatesigningrequests":       true,
	"apiservices":                      true,
	"tokenreviews":                     true,
	"subjectaccessreviews":             true,
	"selfsubjectaccessreviews":         true,
	"selfsubjectrulesreviews":          true,
	"storageclasses":                   true,
	"volumeattachments":                true,
	"mutatingwebhookconfigurations":    true,
	"validatingwebhookconfigurations":  true,
	"customresourcedefinitions":        true,
}

func main() {
	var (
		port      = flag.String("port", "8081", "HTTP server port")
		dbURL     = flag.String("db", os.Getenv("POSTGRES_URL"), "Postgres connection URL")
		grpcPort  = flag.String("grpc-port", "5060", "Falco gRPC server port")
	)
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("[M5] --db or POSTGRES_URL env var required")
	}

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("[M5] db open failed: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("[M5] failed to ping db: %v", err)
	}

	// 1. Falco Ingestion Pipeline
	falcoChan := make(chan *falco.RuntimeEvent, 100)
	dedup := falco.NewDeduplicator(500 * time.Millisecond)

	http.Handle("/api/v1/falco/event", &falco.FalcoWebhookHandler{EventChan: falcoChan})
	falco.StartGrpcServer(*grpcPort, falcoChan)

	// Ingest Falco telemetry events asynchronously
	go func() {
		for ev := range falcoChan {
			// If scan ID is missing from Falco payload, default to active scan ID or skip
			if ev.ScanID == "" {
				var activeScanID string
				err := db.QueryRow("SELECT id FROM scans WHERE status = 'running' LIMIT 1").Scan(&activeScanID)
				if err != nil || activeScanID == "" {
					continue
				}
				ev.ScanID = activeScanID
			}

			sig := falco.EventSignature(ev.ScanID, ev.Namespace, ev.PodName, ev.Verb, ev.Resource)
			if !dedup.ShouldProcess(sig) {
				continue
			}

			podID, createdAt, err := resolvePodID(db, ev.ScanID, ev.Namespace, ev.PodName)
			if err != nil || podID == "" {
				continue
			}

			// Temporal window calculation: startup vs steady-state
			isStartup := time.Since(createdAt) <= 60*time.Second
			scope := "namespace"
			if clusterScopedResources[strings.ToLower(ev.Resource)] {
				scope = "cluster"
			}

			_ = recordObservation(db, ev.ScanID, podID, ev.Verb, ev.Resource, ev.APIGroup, scope, isStartup)
		}
	}()

	// Cleanup deduplicator cache periodically
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			dedup.CleanOldSignatures()
		}
	}()

	// 2. HTTP Server Endpoints
	http.HandleFunc("/api/v1/event", handleEvent(db))
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("[M5] starting runtime monitor HTTP server on port %s", *port)
	if err := http.ListenAndServe(":"+*port, nil); err != nil {
		log.Fatalf("[M5] listen and serve failed: %v", err)
	}
}

func handleEvent(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req EventRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.ScanID == "" || req.PodName == "" || req.Namespace == "" || req.Verb == "" || req.Resource == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		podID, createdAt, err := resolvePodID(db, req.ScanID, req.Namespace, req.PodName)
		if err != nil {
			log.Printf("[M5] failed to resolve pod ID for %s/%s: %v", req.Namespace, req.PodName, err)
			http.Error(w, "Failed to resolve pod", http.StatusInternalServerError)
			return
		}

		if podID == "" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ignored", "reason": "pod_not_in_scan"})
			return
		}

		// Sliding startup detection window check
		isStartup := req.IsStartup || time.Since(createdAt) <= 60*time.Second

		scope := "namespace"
		if clusterScopedResources[strings.ToLower(req.Resource)] {
			scope = "cluster"
		}

		err = recordObservation(db, req.ScanID, podID, req.Verb, req.Resource, req.APIGroup, scope, isStartup)
		if err != nil {
			log.Printf("[M5] failed to record observation: %v", err)
			http.Error(w, "Failed to record observation", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "recorded"})
	}
}

func resolvePodID(db *sql.DB, scanID, namespace, rawPodName string) (string, time.Time, error) {
	cleanedName := cleanPodName(rawPodName)
	cacheKey := scanID + "/" + namespace + "/" + cleanedName

	cacheMu.RLock()
	entry, found := podCache[cacheKey]
	cacheMu.RUnlock()

	if found {
		return entry.ID, entry.CreatedAt, nil
	}

	var podID string
	var createdAt time.Time
	err := db.QueryRow(
		`SELECT id, created_at FROM pods 
		 WHERE scan_id = $1 AND namespace = $2 AND (pod_name = $3 OR pod_name = $4)`,
		scanID, namespace, rawPodName, cleanedName,
	).Scan(&podID, &createdAt)

	if err == sql.ErrNoRows {
		err = db.QueryRow(
			`SELECT id, created_at FROM pods 
			 WHERE scan_id = $1 AND namespace = $2 AND $3 LIKE pod_name || '%' 
			 ORDER BY length(pod_name) DESC LIMIT 1`,
			scanID, namespace, rawPodName,
		).Scan(&podID, &createdAt)
	}

	if err != nil && err != sql.ErrNoRows {
		return "", time.Time{}, err
	}

	if podID != "" {
		cacheMu.Lock()
		podCache[cacheKey] = PodCacheEntry{ID: podID, CreatedAt: createdAt}
		cacheMu.Unlock()
	}

	return podID, createdAt, nil
}

func cleanPodName(name string) string {
	reDep := regexp.MustCompile(`-[a-f0-9]{8,10}-[a-z0-9]{5}$`)
	reJob := regexp.MustCompile(`-[a-z0-9]{5}$`)

	if reDep.MatchString(name) {
		return reDep.ReplaceAllString(name, "")
	}
	if reJob.MatchString(name) {
		return reJob.ReplaceAllString(name, "")
	}
	return name
}

func recordObservation(db *sql.DB, scanID, podID, verb, resource, apiGroup, scope string, isStartup bool) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var obsID int64
	var observedCount int
	var isStartupOnly bool
	var firstSeen, lastSeen sql.NullTime

	err = tx.QueryRow(
		`SELECT id, observed_count, is_startup_only, first_seen, last_seen 
		 FROM permission_observations 
		 WHERE scan_id = $1 AND pod_id = $2 AND source = 'runtime' AND verb = $3 AND resource = $4 AND api_group = $5`,
		scanID, podID, verb, resource, apiGroup,
	).Scan(&obsID, &observedCount, &isStartupOnly, &firstSeen, &lastSeen)

	now := time.Now()

	if err == sql.ErrNoRows {
		_, err = tx.Exec(
			`INSERT INTO permission_observations 
			   (scan_id, pod_id, source, verb, resource, api_group, scope, first_observed_at, last_observed_at, observed_count, is_startup_only, first_seen, last_seen, execution_frequency)
			 VALUES ($1, $2, 'runtime', $3, $4, $5, $6, $7, $7, 1, $8, $7, $7, 1.0)`,
			scanID, podID, verb, resource, apiGroup, scope, now, isStartup,
		)
	} else if err == nil {
		newStartupOnly := isStartupOnly && isStartup
		newCount := observedCount + 1

		var fs time.Time
		if firstSeen.Valid {
			fs = firstSeen.Time
		} else {
			fs = now
		}
		days := now.Sub(fs).Hours() / 24.0
		if days < 0.01 {
			days = 0.01
		}
		freq := float64(newCount) / days

		_, err = tx.Exec(
			`UPDATE permission_observations 
			 SET last_observed_at = $1, 
			     observed_count = $2, 
			     is_startup_only = $3,
			     last_seen = $1,
			     execution_frequency = $4
			 WHERE id = $5`,
			now, newCount, newStartupOnly, freq, obsID,
		)
	}

	if err != nil {
		return err
	}

	return tx.Commit()
}
