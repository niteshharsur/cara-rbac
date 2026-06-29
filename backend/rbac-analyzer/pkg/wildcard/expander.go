package wildcard

import (
	rbacv1 "k8s.io/api/rbac/v1"
	"cara-rbac/rbac-analyzer/pkg/binding"
	"cara-rbac/rbac-analyzer/pkg/model"
)

// AllVerbs is the complete set of Kubernetes RBAC verbs.
// Wildcard "*" expands to all of these.
var AllVerbs = []string{
	"get", "list", "watch",
	"create", "update", "patch", "delete", "deletecollection",
	"impersonate", "bind", "escalate", "approve", "attest",
}

// CanonicalResource represents a standard Kubernetes API resource with its API group and version.
type CanonicalResource struct {
	Name       string
	APIGroup   string
	APIVersion string
}

// ResourceRegistry maps and resolves canonical Kubernetes resources.
type ResourceRegistry struct {
	resources []CanonicalResource
}

// DefaultRegistry is the registry of core and common extended K8s resources.
var DefaultRegistry = &ResourceRegistry{
	resources: []CanonicalResource{
		// Core Group (v1)
		{Name: "pods", APIGroup: "", APIVersion: "v1"},
		{Name: "pods/log", APIGroup: "", APIVersion: "v1"},
		{Name: "pods/exec", APIGroup: "", APIVersion: "v1"},
		{Name: "pods/portforward", APIGroup: "", APIVersion: "v1"},
		{Name: "pods/proxy", APIGroup: "", APIVersion: "v1"},
		{Name: "services", APIGroup: "", APIVersion: "v1"},
		{Name: "endpoints", APIGroup: "", APIVersion: "v1"},
		{Name: "secrets", APIGroup: "", APIVersion: "v1"},
		{Name: "configmaps", APIGroup: "", APIVersion: "v1"},
		{Name: "namespaces", APIGroup: "", APIVersion: "v1"},
		{Name: "nodes", APIGroup: "", APIVersion: "v1"},
		{Name: "persistentvolumes", APIGroup: "", APIVersion: "v1"},
		{Name: "persistentvolumeclaims", APIGroup: "", APIVersion: "v1"},
		{Name: "events", APIGroup: "", APIVersion: "v1"},
		{Name: "serviceaccounts", APIGroup: "", APIVersion: "v1"},
		{Name: "replicationcontrollers", APIGroup: "", APIVersion: "v1"},
		{Name: "resourcequotas", APIGroup: "", APIVersion: "v1"},
		{Name: "limitranges", APIGroup: "", APIVersion: "v1"},
		{Name: "bindings", APIGroup: "", APIVersion: "v1"},

		// Apps (apps/v1)
		{Name: "deployments", APIGroup: "apps", APIVersion: "v1"},
		{Name: "daemonsets", APIGroup: "apps", APIVersion: "v1"},
		{Name: "statefulsets", APIGroup: "apps", APIVersion: "v1"},
		{Name: "replicasets", APIGroup: "apps", APIVersion: "v1"},
		{Name: "controllerrevisions", APIGroup: "apps", APIVersion: "v1"},

		// Batch (batch/v1)
		{Name: "jobs", APIGroup: "batch", APIVersion: "v1"},
		{Name: "cronjobs", APIGroup: "batch", APIVersion: "v1"},

		// RBAC (rbac.authorization.k8s.io/v1)
		{Name: "roles", APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1"},
		{Name: "clusterroles", APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1"},
		{Name: "rolebindings", APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1"},
		{Name: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", APIVersion: "v1"},

		// Networking (networking.k8s.io/v1)
		{Name: "ingresses", APIGroup: "networking.k8s.io", APIVersion: "v1"},
		{Name: "networkpolicies", APIGroup: "networking.k8s.io", APIVersion: "v1"},

		// Storage (storage.k8s.io/v1)
		{Name: "storageclasses", APIGroup: "storage.k8s.io", APIVersion: "v1"},
		{Name: "volumeattachments", APIGroup: "storage.k8s.io", APIVersion: "v1"},

		// Policy (policy/v1)
		{Name: "poddisruptionbudgets", APIGroup: "policy", APIVersion: "v1"},

		// Autoscaling (autoscaling/v2)
		{Name: "horizontalpodautoscalers", APIGroup: "autoscaling", APIVersion: "v2"},
	},
}

// GetAPIGroup fetches the canonical group for a resource name.
func (r *ResourceRegistry) GetAPIGroup(resName string) string {
	for _, cr := range r.resources {
		if cr.Name == resName {
			return cr.APIGroup
		}
	}
	return ""
}

// ExpandAll implements Algorithm 1 from the CARA-RBAC paper.
// It expands wildcard verbs ("*") and wildcard resources ("*") in PolicyRules
// to their concrete enumerated counterparts, returning a flat slice of
// deduplicated PermissionTuples.
func ExpandAll(resolved []binding.ResolvedRole) []model.PermissionTuple {
	seen := make(map[string]struct{})
	var out []model.PermissionTuple

	for _, rr := range resolved {
		tuples := expandRules(rr.Rules, rr.Scope, rr.Source)
		for _, t := range tuples {
			k := t.Key()
			if _, exists := seen[k]; !exists {
				seen[k] = struct{}{}
				out = append(out, t)
			}
		}
	}
	return out
}

// expandRules expands a single PolicyRule slice to PermissionTuples.
func expandRules(rules []rbacv1.PolicyRule, scope model.Scope, sourceRole string) []model.PermissionTuple {
	var out []model.PermissionTuple

	for _, rule := range rules {
		verbs := expandVerbs(rule.Verbs)
		resources := expandResources(rule.Resources, rule.APIGroups)

		for _, verb := range verbs {
			for _, res := range resources {
				effectiveScope := scope
				if len(rule.ResourceNames) > 0 {
					effectiveScope = model.ScopeResourceSpecific
				}

				apiGroup := ""
				if len(rule.APIGroups) == 1 && rule.APIGroups[0] != "*" {
					apiGroup = rule.APIGroups[0]
				} else {
					apiGroup = DefaultRegistry.GetAPIGroup(res.name)
				}

				out = append(out, model.PermissionTuple{
					Verb:          verb,
					Resource:      res.name,
					APIGroup:      apiGroup,
					Scope:         effectiveScope,
					SourceRole:    sourceRole,
					ResourceNames: rule.ResourceNames,
				})
			}
		}
	}
	return out
}

// expandVerbs replaces "*" with all known verbs.
func expandVerbs(verbs []string) []string {
	for _, v := range verbs {
		if v == "*" {
			return AllVerbs
		}
	}
	return verbs
}

type resourceEntry struct {
	name string
}

// expandResources replaces "*" resource with all known resources, filtered by API group.
func expandResources(resources, apiGroups []string) []resourceEntry {
	hasWildcard := false
	for _, r := range resources {
		if r == "*" {
			hasWildcard = true
			break
		}
	}

	if !hasWildcard {
		out := make([]resourceEntry, len(resources))
		for i, r := range resources {
			out[i] = resourceEntry{name: r}
		}
		return out
	}

	groupSet := make(map[string]struct{})
	for _, g := range apiGroups {
		groupSet[g] = struct{}{}
	}
	wildcardAll := len(groupSet) == 0 || func() bool {
		_, ok := groupSet["*"]
		return ok
	}()

	var out []resourceEntry
	for _, cr := range DefaultRegistry.resources {
		if wildcardAll {
			out = append(out, resourceEntry{name: cr.Name})
			continue
		}
		if _, ok := groupSet[cr.APIGroup]; ok {
			out = append(out, resourceEntry{name: cr.Name})
		}
	}
	return out
}
