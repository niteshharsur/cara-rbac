package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"

	_ "github.com/lib/pq"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type Classification struct {
	Verb     string
	Resource string
	Scope    string
	Class    string
}

type PodRecord struct {
	ID             string
	PodName        string
	Namespace      string
	ServiceAccount string
}

type SplitRecommendation struct {
	ServiceAccount string   `json:"service_account"`
	SharingPods    []string `json:"sharing_pods"`
	Action         string   `json:"action"`
}

func main() {
	var (
		scanID   = flag.String("scan-id", "", "UUID of the scan to minimize (required)")
		dbURL    = flag.String("db", os.Getenv("POSTGRES_URL"), "Postgres connection URL")
		keepSFP  = flag.Bool("keep-sfp", true, "Whether to retain Static False Positive (SFP) permissions")
		keepSOP  = flag.Bool("keep-sop", true, "Whether to retain Startup-Only (SOP) permissions")
	)
	flag.Parse()

	if *scanID == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *dbURL == "" {
		log.Fatal("[M7] --db or POSTGRES_URL env var required")
	}

	log.Printf("[M7] starting RBAC minimization  scan=%s", *scanID)

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("[M7] db open failed: %v", err)
	}
	defer db.Close()

	// 1. Fetch pods for the scan
	pods, err := fetchScanPods(db, *scanID)
	if err != nil {
		log.Fatalf("[M7] failed to fetch pods: %v", err)
	}
	if len(pods) == 0 {
		log.Printf("[M7] warning: no pods found in DB for scan %s. Nothing to minimize.", *scanID)
		return
	}

	// 2. Generate Role-Splitting Recommendations
	splitRecs := generateRoleSplittingRecommendations(pods)
	splitRecsJSON, _ := json.Marshal(splitRecs)

	// 3. Process each pod
	for _, p := range pods {
		classes, err := fetchClassifications(db, *scanID, p.ID)
		if err != nil {
			log.Fatalf("[M7] failed to fetch classifications for pod %s/%s: %v", p.Namespace, p.PodName, err)
		}

		if len(classes) == 0 {
			log.Printf("[M7] no classifications found for pod %s/%s. Skipping.", p.Namespace, p.PodName)
			continue
		}

		// Separate rules by scope and group verbs
		nsRulesMap := make(map[string]map[string]bool) // Key: "apiGroup/resource", Value: set of verbs
		clusterRulesMap := make(map[string]map[string]bool)

		originalCount := len(classes)
		minimizedCount := 0

		for _, cl := range classes {
			keep := false
			switch cl.Class {
			case "RP", "DP":
				keep = true
			case "SFP":
				keep = *keepSFP
			case "SOP":
				keep = *keepSOP
			case "DRP":
				keep = *keepSOP
			case "CEP":
				keep = false
			}

			// Fine-grained Mutating Verb Minimization Safeguard:
			// Strip mutating verbs classified as SFP (static but unused at runtime) to ensure security.
			isMutating := cl.Verb == "create" || cl.Verb == "update" || cl.Verb == "patch" || cl.Verb == "delete" || cl.Verb == "deletecollection"
			if cl.Class == "SFP" && isMutating {
				keep = false
			}

			if keep {
				minimizedCount++
				apiGroup := ""
				resource := cl.Resource
				if parts := strings.Split(cl.Resource, "."); len(parts) > 1 && !strings.Contains(cl.Resource, "authorization.k8s.io") {
					apiGroup = parts[1]
					resource = parts[0]
				}

				ruleKey := apiGroup + "/" + resource
				if cl.Scope == "cluster" {
					if _, ok := clusterRulesMap[ruleKey]; !ok {
						clusterRulesMap[ruleKey] = make(map[string]bool)
					}
					clusterRulesMap[ruleKey][cl.Verb] = true
				} else {
					if _, ok := nsRulesMap[ruleKey]; !ok {
						nsRulesMap[ruleKey] = make(map[string]bool)
					}
					nsRulesMap[ruleKey][cl.Verb] = true
				}
			}
		}

		// Generate minimized Kubernetes manifests
		var manifestYAMLs []string

		// Namespace Role
		if len(nsRulesMap) > 0 {
			role := rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "Role",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      p.PodName + "-minimized",
					Namespace: p.Namespace,
					Labels: map[string]string{
						"cara-rbac/scan-id": *scanID,
						"cara-rbac/pod-id":  p.ID,
					},
				},
				Rules: buildPolicyRules(nsRulesMap),
			}
			rYAML, err := yaml.Marshal(role)
			if err != nil {
				log.Fatalf("[M7] failed to marshal Role: %v", err)
			}
			manifestYAMLs = append(manifestYAMLs, string(rYAML))

			// RoleBinding
			binding := rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "RoleBinding",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      p.PodName + "-minimized-binding",
					Namespace: p.Namespace,
					Labels: map[string]string{
						"cara-rbac/scan-id": *scanID,
						"cara-rbac/pod-id":  p.ID,
					},
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      p.ServiceAccount,
						Namespace: p.Namespace,
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     role.Name,
				},
			}
			bYAML, err := yaml.Marshal(binding)
			if err != nil {
				log.Fatalf("[M7] failed to marshal RoleBinding: %v", err)
			}
			manifestYAMLs = append(manifestYAMLs, string(bYAML))
		}

		// ClusterRole
		if len(clusterRulesMap) > 0 {
			cRole := rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRole",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: p.PodName + "-minimized-cluster",
					Labels: map[string]string{
						"cara-rbac/scan-id": *scanID,
						"cara-rbac/pod-id":  p.ID,
					},
				},
				Rules: buildPolicyRules(clusterRulesMap),
			}
			crYAML, err := yaml.Marshal(cRole)
			if err != nil {
				log.Fatalf("[M7] failed to marshal ClusterRole: %v", err)
			}
			manifestYAMLs = append(manifestYAMLs, string(crYAML))

			// ClusterRoleBinding
			cBinding := rbacv1.ClusterRoleBinding{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRoleBinding",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: p.PodName + "-minimized-cluster-binding",
					Labels: map[string]string{
						"cara-rbac/scan-id": *scanID,
						"cara-rbac/pod-id":  p.ID,
					},
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      p.ServiceAccount,
						Namespace: p.Namespace,
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     cRole.Name,
				},
			}
			cbYAML, err := yaml.Marshal(cBinding)
			if err != nil {
				log.Fatalf("[M7] failed to marshal ClusterRoleBinding: %v", err)
			}
			manifestYAMLs = append(manifestYAMLs, string(cbYAML))
		}

		combinedYAML := strings.Join(manifestYAMLs, "---\n")

		// Create rollback script
		rollbackScript := buildRollbackScript(p.PodName, p.Namespace, len(clusterRulesMap) > 0)

		// Calculate reduction percentage
		reductionPct := 0.0
		if originalCount > 0 {
			reductionPct = (1.0 - float64(minimizedCount)/float64(originalCount)) * 100.0
		}

		// Perform kubectl dry-run apply verification check
		deployStatus, deployDetails := verifyDeployability(combinedYAML)

		// Write minimization results to DB
		err = saveMinimizationResult(db, *scanID, p.ID, originalCount, minimizedCount, reductionPct, combinedYAML, rollbackScript, deployStatus, deployDetails, string(splitRecsJSON))
		if err != nil {
			log.Fatalf("[M7] failed to save results: %v", err)
		}

		log.Printf("[M7] minimized pod=%s/%s  original=%d  minimized=%d  reduction=%.2f%%  deployable=%s",
			p.Namespace, p.PodName, originalCount, minimizedCount, reductionPct, deployStatus)
	}

	log.Println("[M7] minimization completed successfully.")
}

func generateRoleSplittingRecommendations(pods []PodRecord) []SplitRecommendation {
	saMap := make(map[string][]string) // Key: saName, Value: list of podNames
	for _, p := range pods {
		saMap[p.ServiceAccount] = append(saMap[p.ServiceAccount], p.PodName)
	}

	var recs []SplitRecommendation
	for sa, sharing := range saMap {
		if len(sharing) > 1 {
			recs = append(recs, SplitRecommendation{
				ServiceAccount: sa,
				SharingPods:    sharing,
				Action:         fmt.Sprintf("Split shared ServiceAccount %q into unique accounts for each pod (%s) to isolate security contexts.", sa, strings.Join(sharing, ", ")),
			})
		}
	}
	return recs
}

func verifyDeployability(yamlContent string) (string, string) {
	if yamlContent == "" {
		return "passed", "Empty manifest; nothing to deploy."
	}

	// Verify if kubectl is available
	if _, err := exec.LookPath("kubectl"); err != nil {
		// Fallback check: verify wsl.exe kubectl
		if _, wslErr := exec.LookPath("wsl.exe"); wslErr == nil {
			cmd := exec.Command("wsl.exe", "kubectl", "apply", "--dry-run=client", "-f", "-")
			cmd.Stdin = strings.NewReader(yamlContent)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err == nil {
				return "passed", "kubectl dry-run applied successfully via WSL"
			} else {
				return "failed", fmt.Sprintf("WSL kubectl validation error: %s", stderr.String())
			}
		}
		return "skipped", "kubectl binary not found on PATH"
	}

	cmd := exec.Command("kubectl", "apply", "--dry-run=client", "-f", "-")
	cmd.Stdin = strings.NewReader(yamlContent)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "failed", fmt.Sprintf("Kubernetes schema policy validation error: %s", stderr.String())
	}

	return "passed", "kubectl dry-run client validation succeeded."
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

func fetchClassifications(db *sql.DB, scanID, podID string) ([]Classification, error) {
	rows, err := db.Query(`
		SELECT verb, resource, scope, class 
		FROM classifications 
		WHERE scan_id = $1 AND pod_id = $2`,
		scanID, podID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var classes []Classification
	for rows.Next() {
		var c Classification
		if err := rows.Scan(&c.Verb, &c.Resource, &c.Scope, &c.Class); err != nil {
			return nil, err
		}
		classes = append(classes, c)
	}
	return classes, nil
}

func buildPolicyRules(rulesMap map[string]map[string]bool) []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule
	for key, verbsSet := range rulesMap {
		parts := strings.Split(key, "/")
		apiGroup := parts[0]
		resource := parts[1]

		var verbs []string
		for v := range verbsSet {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)

		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{apiGroup},
			Resources: []string{resource},
			Verbs:     verbs,
		})
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Resources[0] == rules[j].Resources[0] {
			return rules[i].APIGroups[0] < rules[j].APIGroups[0]
		}
		return rules[i].Resources[0] < rules[j].Resources[0]
	})

	return rules
}

func buildRollbackScript(podName, namespace string, hasCluster bool) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString(fmt.Sprintf("# Rollback minimized CARA-RBAC policies for pod %s/%s\n\n", namespace, podName))
	
	sb.WriteString(fmt.Sprintf("echo \"Deleting minimized Role and RoleBinding...\"\n"))
	sb.WriteString(fmt.Sprintf("kubectl delete rolebinding %s-minimized-binding -n %s --ignore-not-found\n", podName, namespace))
	sb.WriteString(fmt.Sprintf("kubectl delete role %s-minimized -n %s --ignore-not-found\n", podName, namespace))
	
	if hasCluster {
		sb.WriteString(fmt.Sprintf("\necho \"Deleting minimized ClusterRole and ClusterRoleBinding...\"\n"))
		sb.WriteString(fmt.Sprintf("kubectl delete clusterrolebinding %s-minimized-cluster-binding --ignore-not-found\n", podName))
		sb.WriteString(fmt.Sprintf("kubectl delete clusterrole %s-minimized-cluster --ignore-not-found\n", podName))
	}
	
	sb.WriteString("\necho \"Rollback complete. Note: original role bindings must be manually re-applied or enabled.\"\n")
	return sb.String()
}

func saveMinimizationResult(db *sql.DB, scanID, podID string, originalCount, minimizedCount int, reductionPct float64, minimizedYAML, rollbackScript, validationStatus, validationDetails, splitRecs string) error {
	_, err := db.Exec(
		`INSERT INTO minimization_results 
		   (scan_id, pod_id, original_count, minimized_count, reduction_pct, minimized_yaml, rollback_script, validation_status, validation_details, role_splitting_suggestions)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT DO NOTHING`,
		scanID, podID, originalCount, minimizedCount, reductionPct, minimizedYAML, rollbackScript, validationStatus, validationDetails, splitRecs,
	)
	return err
}

func validateManifest(yamlContent string) string {
	if yamlContent == "" {
		return "passed"
	}
	docs := strings.Split(yamlContent, "---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var meta metav1.TypeMeta
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			return "failed"
		}
		if meta.Kind == "Role" {
			var r rbacv1.Role
			if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
				return "failed"
			}
			if len(r.Rules) == 0 {
				return "failed"
			}
		}
	}
	return "passed"
}
