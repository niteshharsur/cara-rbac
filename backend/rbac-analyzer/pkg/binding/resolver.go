package binding

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"cara-rbac/rbac-analyzer/pkg/model"
)

// ResolvedRole is a Role/ClusterRole whose rules have been bound to a specific pod.
type ResolvedRole struct {
	Rules  []rbacv1.PolicyRule
	Scope  model.Scope
	Source string // role name
}

// Resolver resolves the chain: Pod → ServiceAccount → RoleBinding/ClusterRoleBinding → Role/ClusterRole.
type Resolver struct {
	roles           map[string]rbacv1.Role           // key: "<namespace>/<name>"
	clusterRoles    map[string]rbacv1.ClusterRole    // key: "<name>"
	roleBindings    []rbacv1.RoleBinding
	clusterBindings []rbacv1.ClusterRoleBinding
}

// NewResolver constructs a Resolver from parsed manifest objects.
func NewResolver(
	roles map[string]rbacv1.Role,
	clusterRoles map[string]rbacv1.ClusterRole,
	roleBindings []rbacv1.RoleBinding,
	clusterBindings []rbacv1.ClusterRoleBinding,
) *Resolver {
	return &Resolver{
		roles:           roles,
		clusterRoles:    clusterRoles,
		roleBindings:    roleBindings,
		clusterBindings: clusterBindings,
	}
}

// ResolveForPod walks every binding in the manifest set and returns the set of
// (rules, scope, source-role) tuples that apply to the given pod's ServiceAccount.
func (r *Resolver) ResolveForPod(pod corev1.Pod) []ResolvedRole {
	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	ns := pod.Namespace

	var resolved []ResolvedRole

	// ── RoleBindings (namespace-scoped) ──────────────────────────────────────
	for _, rb := range r.roleBindings {
		// Binding must be in the same namespace as the pod (or cluster-wide ns="")
		if rb.Namespace != ns && rb.Namespace != "" {
			continue
		}
		if !bindsServiceAccount(rb.Subjects, saName, ns) {
			continue
		}

		switch rb.RoleRef.Kind {
		case "Role":
			key := rb.Namespace + "/" + rb.RoleRef.Name
			if role, ok := r.roles[key]; ok {
				resolved = append(resolved, ResolvedRole{
					Rules:  role.Rules,
					Scope:  model.ScopeNamespace,
					Source: role.Name,
				})
			}
		case "ClusterRole":
			// ClusterRole bound via RoleBinding → namespace-scoped
			if cr, ok := r.clusterRoles[rb.RoleRef.Name]; ok {
				resolved = append(resolved, ResolvedRole{
					Rules:  cr.Rules,
					Scope:  model.ScopeNamespace, // key subtlety: namespace-scoped when via RoleBinding
					Source: cr.Name,
				})
			}
		}
	}

	// ── ClusterRoleBindings (cluster-scoped) ──────────────────────────────────
	for _, crb := range r.clusterBindings {
		if !bindsServiceAccount(crb.Subjects, saName, ns) {
			continue
		}
		if cr, ok := r.clusterRoles[crb.RoleRef.Name]; ok {
			resolved = append(resolved, ResolvedRole{
				Rules:  cr.Rules,
				Scope:  model.ScopeCluster,
				Source: cr.Name,
			})
		}
	}

	return resolved
}

// bindsServiceAccount returns true if any subject in the list is a ServiceAccount
// with the given name in the given namespace.
func bindsServiceAccount(subjects []rbacv1.Subject, saName, ns string) bool {
	for _, s := range subjects {
		if s.Kind != "ServiceAccount" {
			continue
		}
		if s.Name != saName {
			continue
		}
		// Subject namespace must match pod namespace, OR be empty (cluster-wide)
		if s.Namespace == ns || s.Namespace == "" {
			return true
		}
	}
	return false
}
