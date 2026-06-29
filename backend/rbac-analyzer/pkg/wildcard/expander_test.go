package wildcard

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"cara-rbac/rbac-analyzer/pkg/binding"
	"cara-rbac/rbac-analyzer/pkg/model"
)

func TestExpandVerbs(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{
			Verbs:     []string{"*"},
			Resources: []string{"pods"},
		},
	}
	tuples := expandRules(rules, model.ScopeNamespace, "test-role")

	// Verify that the "*" verb expanded to all standard verbs in AllVerbs
	if len(tuples) != len(AllVerbs) {
		t.Fatalf("expected verb wildcard to expand to %d verbs, got %d", len(AllVerbs), len(tuples))
	}

	verbSet := make(map[string]bool)
	for _, tuple := range tuples {
		verbSet[tuple.Verb] = true
	}

	for _, v := range AllVerbs {
		if !verbSet[v] {
			t.Errorf("expected verb %s to be resolved, but it was missing", v)
		}
	}
}

func TestExpandResources(t *testing.T) {
	// Test case 1: Wildcard resource matching apps API group
	rules := []rbacv1.PolicyRule{
		{
			Verbs:     []string{"get"},
			APIGroups: []string{"apps"},
			Resources: []string{"*"},
		},
	}
	tuples := expandRules(rules, model.ScopeNamespace, "test-role")

	// Find how many apps resources are defined in DefaultRegistry
	expectedCount := 0
	for _, res := range DefaultRegistry.resources {
		if res.APIGroup == "apps" {
			expectedCount++
		}
	}

	if len(tuples) != expectedCount {
		t.Fatalf("expected %d resolved apps resources, got %d", expectedCount, len(tuples))
	}

	// Verify apps resource details (e.g. deployments, statefulsets)
	hasDeployments := false
	for _, tuple := range tuples {
		if tuple.Resource == "deployments" {
			hasDeployments = true
			if tuple.APIGroup != "apps" {
				t.Errorf("expected deployments to have APIGroup 'apps', got '%s'", tuple.APIGroup)
			}
		}
	}
	if !hasDeployments {
		t.Error("expected deployments to be resolved under apps API group")
	}

	// Test case 2: Wildcard resource without specifying API group (or "*" API group) -> expands to all resources
	rulesAll := []rbacv1.PolicyRule{
		{
			Verbs:     []string{"get"},
			APIGroups: []string{"*"},
			Resources: []string{"*"},
		},
	}
	tuplesAll := expandRules(rulesAll, model.ScopeNamespace, "test-role")
	if len(tuplesAll) != len(DefaultRegistry.resources) {
		t.Fatalf("expected wildcard all resources to expand to %d, got %d", len(DefaultRegistry.resources), len(tuplesAll))
	}
}

func TestExpandAllDeduplication(t *testing.T) {
	resolved := []binding.ResolvedRole{
		{
			Source: "role-a",
			Scope:  model.ScopeNamespace,
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get"},
					Resources: []string{"pods"},
				},
			},
		},
		{
			Source: "role-b",
			Scope:  model.ScopeNamespace,
			Rules: []rbacv1.PolicyRule{
				{
					// Duplicate rule mapping the same verb, resource, and namespace scope
					Verbs:     []string{"get"},
					Resources: []string{"pods"},
				},
			},
		},
	}

	tuples := ExpandAll(resolved)

	// Since they resolve to identical (verb, resource, namespace) configurations, they should be deduplicated to 1 tuple!
	if len(tuples) != 1 {
		t.Fatalf("expected duplicate rules to be deduplicated to 1, got %d", len(tuples))
	}

	if tuples[0].Verb != "get" || tuples[0].Resource != "pods" {
		t.Errorf("unexpected resolved tuple: %+v", tuples[0])
	}
}
