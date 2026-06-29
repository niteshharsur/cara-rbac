package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"cara-rbac/rbac-analyzer/pkg/binding"
	"cara-rbac/rbac-analyzer/pkg/wildcard"
)

type PodRecord struct {
	ID             string
	PodName        string
	Namespace      string
	ServiceAccount string
}

// Metrics
var (
	watchReconnectCount int64
	streamLatencyMs     int64
	cacheSyncDurationMs int64
)

func main() {
	var (
		scanID     = flag.String("scan-id", "", "UUID of the parent scan record in Postgres (optional, triggers one-off collection)")
		dbURL      = flag.String("db", os.Getenv("POSTGRES_URL"), "Postgres connection URL")
		kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig file (optional)")
		watchMode  = flag.Bool("watch", true, "Run in real-time stream watch mode as a background daemon")
		graphURL   = flag.String("graph-url", "http://localhost:8082", "Graph Service sync endpoint URL")
	)
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("[M4] --db or POSTGRES_URL env var required")
	}

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("[M4] db open failed: %v", err)
	}
	defer db.Close()

	clientset, err := buildK8sClient(*kubeconfig)
	if err != nil {
		log.Fatalf("[M4] failed to connect to Kubernetes cluster: %v", err)
	}

	// 1. One-off mode (backward compatibility)
	if *scanID != "" {
		log.Printf("[M4] running one-off cluster context collection for scan=%s", *scanID)
		err = runOneOffCollection(db, clientset, *scanID, *graphURL)
		if err != nil {
			log.Fatalf("[M4] one-off collection failed: %v", err)
		}
		return
	}

	// 2. Watchdog Stream Daemon mode
	if *watchMode {
		log.Println("[M4] starting cluster collector in real-time watchdog stream mode")
		runWatchdogMode(db, clientset, *graphURL)
	} else {
		log.Println("[M4] neither --scan-id nor --watch set. Exiting.")
	}
}

func runOneOffCollection(db *sql.DB, clientset *kubernetes.Clientset, scanID, graphURL string) error {
	pods, err := fetchScanPods(db, scanID)
	if err != nil {
		return fmt.Errorf("failed to fetch pods: %w", err)
	}
	if len(pods) == 0 {
		log.Printf("[M4] warning: no pods found in db for scan %s. Skipping.", scanID)
		return nil
	}

	ctx := context.Background()
	liveRoles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	liveClusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	liveRoleBindings, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	liveClusterBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	rolesMap := make(map[string]rbacv1.Role)
	for _, r := range liveRoles.Items {
		rolesMap[r.Namespace+"/"+r.Name] = r
	}
	clusterRolesMap := make(map[string]rbacv1.ClusterRole)
	for _, cr := range liveClusterRoles.Items {
		clusterRolesMap[cr.Name] = cr
	}

	resolver := binding.NewResolver(rolesMap, clusterRolesMap, liveRoleBindings.Items, liveClusterBindings.Items)
	err = syncScanPermissions(db, resolver, scanID, pods)
	if err != nil {
		return err
	}

	// Notify graph service
	triggerGraphSync(scanID, graphURL)
	return nil
}

func runWatchdogMode(db *sql.DB, clientset *kubernetes.Clientset, graphURL string) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	// Create SharedInformerFactory
	factory := informers.NewSharedInformerFactory(clientset, 10*time.Minute)

	roleInformer := factory.Rbac().V1().Roles().Informer()
	clusterRoleInformer := factory.Rbac().V1().ClusterRoles().Informer()
	rbInformer := factory.Rbac().V1().RoleBindings().Informer()
	crbInformer := factory.Rbac().V1().ClusterRoleBindings().Informer()

	triggerChan := make(chan struct{}, 100)
	var lastTriggerMu sync.Mutex
	var lastTriggerTime time.Time

	// Debounce worker to prevent hammering the DB on bulk edits
	go func() {
		for range triggerChan {
			lastTriggerMu.Lock()
			lastTriggerTime = time.Now()
			lastTriggerMu.Unlock()

			// Wait 1 second of silence before processing
			time.Sleep(1 * time.Second)

			lastTriggerMu.Lock()
			silenceDuration := time.Since(lastTriggerTime)
			lastTriggerMu.Unlock()

			if silenceDuration >= 1*time.Second {
				// Drain any additional queued triggers
				for len(triggerChan) > 0 {
					<-triggerChan
				}

				start := time.Now()
				log.Println("[M4] watchdog triggered: syncing active scans from cluster state...")
				err := syncAllActiveScans(db, clientset, graphURL)
				if err != nil {
					log.Printf("[M4] error syncing active scans: %v", err)
					atomic.AddInt64(&watchReconnectCount, 1)
				} else {
					atomic.StoreInt64(&streamLatencyMs, time.Since(start).Milliseconds())
					log.Printf("[M4] sync completed. Stream latency: %d ms", atomic.LoadInt64(&streamLatencyMs))
				}
			}
		}
	}()

	eventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			triggerChan <- struct{}{}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			triggerChan <- struct{}{}
		},
		DeleteFunc: func(obj interface{}) {
			triggerChan <- struct{}{}
		},
	}

	roleInformer.AddEventHandler(eventHandler)
	clusterRoleInformer.AddEventHandler(eventHandler)
	rbInformer.AddEventHandler(eventHandler)
	crbInformer.AddEventHandler(eventHandler)

	startSync := time.Now()
	factory.Start(stopCh)

	log.Println("[M4] waiting for informer cache to sync...")
	if !cache.WaitForCacheSync(stopCh,
		roleInformer.HasSynced,
		clusterRoleInformer.HasSynced,
		rbInformer.HasSynced,
		crbInformer.HasSynced) {
		log.Fatal("[M4] failed to sync informer cache")
	}

	atomic.StoreInt64(&cacheSyncDurationMs, time.Since(startSync).Milliseconds())
	log.Printf("[M4] informer cache synced successfully in %d ms. Watch streams active.", atomic.LoadInt64(&cacheSyncDurationMs))

	// Keep main thread alive
	select {}
}

func syncAllActiveScans(db *sql.DB, clientset *kubernetes.Clientset, graphURL string) error {
	rows, err := db.Query("SELECT id FROM scans WHERE status = 'running'")
	if err != nil {
		return err
	}
	defer rows.Close()

	var activeScanIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			activeScanIDs = append(activeScanIDs, id)
		}
	}

	if len(activeScanIDs) == 0 {
		return nil
	}

	// Fetch live resources once to build base resolver
	ctx := context.Background()
	liveRoles, err := clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	liveClusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	liveRoleBindings, err := clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	liveClusterBindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	rolesMap := make(map[string]rbacv1.Role)
	for _, r := range liveRoles.Items {
		rolesMap[r.Namespace+"/"+r.Name] = r
	}
	clusterRolesMap := make(map[string]rbacv1.ClusterRole)
	for _, cr := range liveClusterRoles.Items {
		clusterRolesMap[cr.Name] = cr
	}

	resolver := binding.NewResolver(rolesMap, clusterRolesMap, liveRoleBindings.Items, liveClusterBindings.Items)

	for _, scanID := range activeScanIDs {
		pods, err := fetchScanPods(db, scanID)
		if err != nil {
			log.Printf("[M4] error fetching pods for scan %s: %v", scanID, err)
			continue
		}
		if len(pods) == 0 {
			continue
		}

		err = syncScanPermissions(db, resolver, scanID, pods)
		if err != nil {
			log.Printf("[M4] error syncing permissions for scan %s: %v", scanID, err)
			continue
		}

		triggerGraphSync(scanID, graphURL)
	}

	return nil
}

func syncScanPermissions(db *sql.DB, resolver *binding.Resolver, scanID string, pods []PodRecord) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear existing cluster observations
	_, err = tx.Exec(`DELETE FROM permission_observations WHERE scan_id = $1 AND source = 'cluster'`, scanID)
	if err != nil {
		return err
	}

	obsStmt, err := tx.Prepare(`
		INSERT INTO permission_observations
		  (scan_id, pod_id, source, verb, resource, api_group, scope, resource_names, source_role)
		VALUES ($1, $2, 'cluster', $3, $4, $5, $6, $7, $8)
	`)
	if err != nil {
		return err
	}
	defer obsStmt.Close()

	for _, p := range pods {
		k8sPod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.PodName,
				Namespace: p.Namespace,
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: p.ServiceAccount,
			},
		}

		resolvedRoles := resolver.ResolveForPod(k8sPod)
		tuples := wildcard.ExpandAll(resolvedRoles)

		for _, t := range tuples {
			_, err = obsStmt.Exec(
				scanID, p.ID,
				t.Verb, t.Resource, t.APIGroup, string(t.Scope),
				sliceToArray(t.ResourceNames),
				t.SourceRole,
			)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func triggerGraphSync(scanID, graphURL string) {
	targetURL := fmt.Sprintf("%s/api/v1/sync/%s", graphURL, scanID)
	resp, err := http.Post(targetURL, "application/json", nil)
	if err != nil {
		log.Printf("[M4] failed to sync graph service for scan %s: %v", scanID, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[M4] graph syncer notified for scan %s. Status: %s", scanID, resp.Status)
}

func fetchScanPods(db *sql.DB, scanID string) ([]PodRecord, error) {
	rows, err := db.Query(`
		SELECT id, pod_name, namespace, service_account 
		FROM pods 
		WHERE scan_id = $1`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pods []PodRecord
	for rows.Next() {
		var p PodRecord
		if err := rows.Scan(&p.ID, &p.PodName, &p.Namespace, &p.ServiceAccount); err != nil {
			return nil, err
		}
		pods = append(pods, p)
	}
	return pods, nil
}

func buildK8sClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	if kubeconfigPath != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err == nil {
			return kubernetes.NewForConfig(config)
		}
	}

	config, err := rest.InClusterConfig()
	if err == nil {
		return kubernetes.NewForConfig(config)
	}

	home := homedir.HomeDir()
	if home != "" {
		defaultPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(defaultPath); err == nil {
			config, err := clientcmd.BuildConfigFromFlags("", defaultPath)
			if err == nil {
				return kubernetes.NewForConfig(config)
			}
		}
	}

	return nil, fmt.Errorf("unable to load Kubernetes config")
}

func sliceToArray(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}
