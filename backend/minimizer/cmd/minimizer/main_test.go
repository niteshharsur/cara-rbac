package main

import (
	"strings"
	"testing"
)

func TestBuildPolicyRules(t *testing.T) {
	// Setup a sample rules map
	rulesMap := map[string]map[string]bool{
		"apps/deployments": {
			"get":  true,
			"list": true,
		},
		"/pods": {
			"create": true,
			"get":    true,
		},
	}

	rules := buildPolicyRules(rulesMap)

	if len(rules) != 2 {
		t.Fatalf("expected 2 policy rules, got %d", len(rules))
	}

	// Verify sorting and contents. deployments should come before pods alphabetically.
	if rules[0].Resources[0] != "deployments" {
		t.Errorf("expected rule 0 resource to be deployments, got %s", rules[0].Resources[0])
	}
	if rules[0].APIGroups[0] != "apps" {
		t.Errorf("expected rule 0 apiGroup to be apps, got %s", rules[0].APIGroups[0])
	}
	if len(rules[0].Verbs) != 2 || rules[0].Verbs[0] != "get" || rules[0].Verbs[1] != "list" {
		t.Errorf("unexpected verbs in deployments rule: %v", rules[0].Verbs)
	}

	if rules[1].Resources[0] != "pods" {
		t.Errorf("expected rule 1 resource to be pods, got %s", rules[1].Resources[0])
	}
	if rules[1].APIGroups[0] != "" {
		t.Errorf("expected rule 1 apiGroup to be empty, got %s", rules[1].APIGroups[0])
	}
	if len(rules[1].Verbs) != 2 || rules[1].Verbs[0] != "create" || rules[1].Verbs[1] != "get" {
		t.Errorf("unexpected verbs in pods rule: %v", rules[1].Verbs)
	}
}

func TestBuildRollbackScript(t *testing.T) {
	podName := "test-pod"
	namespace := "test-ns"

	// Test case 1: Namespace scoped only (no cluster roles)
	scriptNoCluster := buildRollbackScript(podName, namespace, false)
	if !strings.Contains(scriptNoCluster, "kubectl delete rolebinding test-pod-minimized-binding -n test-ns") {
		t.Error("expected rollback script to delete namespace-scoped rolebinding")
	}
	if strings.Contains(scriptNoCluster, "clusterrolebinding") {
		t.Error("did not expect clusterrolebinding deletion in namespace-only rollback script")
	}

	// Test case 2: With cluster roles
	scriptCluster := buildRollbackScript(podName, namespace, true)
	if !strings.Contains(scriptCluster, "kubectl delete clusterrolebinding test-pod-minimized-cluster-binding") {
		t.Error("expected rollback script to delete clusterrolebinding")
	}
	if !strings.Contains(scriptCluster, "kubectl delete clusterrole test-pod-minimized-cluster") {
		t.Error("expected rollback script to delete clusterrole")
	}
}

func TestValidateManifest(t *testing.T) {
	// 1. Empty manifest -> passed
	if status := validateManifest(""); status != "passed" {
		t.Errorf("expected empty manifest to pass, got %s", status)
	}

	// 2. Invalid syntax -> failed
	if status := validateManifest("invalid: yaml: config: {"); status != "failed" {
		t.Errorf("expected invalid syntax to fail, got %s", status)
	}

	// 3. Valid namespace Role & RoleBinding -> passed
	validRoleDoc := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: test-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: test-role
`
	if status := validateManifest(validRoleDoc); status != "passed" {
		t.Errorf("expected valid manifest to pass, got %s", status)
	}

	// 4. Missing required field (rules) in Role -> failed
	invalidRoleDoc := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: default
`
	if status := validateManifest(invalidRoleDoc); status != "failed" {
		t.Errorf("expected invalid role (no rules) to fail, got %s", status)
	}
}
