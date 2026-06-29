package binding

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"cara-rbac/rbac-analyzer/pkg/model"
)

func TestResolveForPod(t *testing.T) {
	// 1. Roles and ClusterRoles setup
	roles := map[string]rbacv1.Role{
		"default/namespace-role": {
			ObjectMeta: metav1.ObjectMeta{Name: "namespace-role", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get", "list"},
					Resources: []string{"pods"},
				},
			},
		},
	}

	clusterRoles := map[string]rbacv1.ClusterRole{
		"cluster-role": {
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-role"},
			Rules: []rbacv1.PolicyRule{
				{
					Verbs:     []string{"get", "list"},
					Resources: []string{"nodes"},
				},
			},
		},
	}

	// 2. RoleBindings and ClusterRoleBindings setup
	roleBindings := []rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "role-binding-sa", Namespace: "default"},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "test-sa",
					Namespace: "default",
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "namespace-role",
			},
		},
		{
			// Binding ClusterRole to Namespace-level RoleBinding -> ScopeNamespace
			ObjectMeta: metav1.ObjectMeta{Name: "role-binding-cr", Namespace: "default"},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "test-sa",
					Namespace: "default",
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "cluster-role",
			},
		},
	}

	clusterBindings := []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-binding-sa"},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "test-sa",
					Namespace: "default",
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "cluster-role",
			},
		},
	}

	resolver := NewResolver(roles, clusterRoles, roleBindings, clusterBindings)

	// Test case 1: Matching pod namespace and ServiceAccount
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{ServiceAccountName: "test-sa"},
	}

	resolved := resolver.ResolveForPod(pod)

	// Expect 3 resolved roles:
	// - Namespace Role binding (Role)
	// - Namespace ClusterRole binding (ClusterRole)
	// - Cluster ClusterRoleBinding (ClusterRole)
	if len(resolved) != 3 {
		t.Fatalf("expected 3 resolved roles, got %d", len(resolved))
	}

	// Verify details
	hasNamespaceRole := false
	hasNamespaceClusterRole := false
	hasClusterClusterRole := false

	for _, rr := range resolved {
		if rr.Source == "namespace-role" && rr.Scope == model.ScopeNamespace {
			hasNamespaceRole = true
		} else if rr.Source == "cluster-role" && rr.Scope == model.ScopeNamespace {
			hasNamespaceClusterRole = true
		} else if rr.Source == "cluster-role" && rr.Scope == model.ScopeCluster {
			hasClusterClusterRole = true
		}
	}

	if !hasNamespaceRole {
		t.Error("expected matching namespace role")
	}
	if !hasNamespaceClusterRole {
		t.Error("expected matching namespace-scoped cluster role binding")
	}
	if !hasClusterClusterRole {
		t.Error("expected matching cluster-scoped cluster role binding")
	}

	// Test case 2: Namespace mismatch
	mismatchPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "other-namespace"},
		Spec:       corev1.PodSpec{ServiceAccountName: "test-sa"},
	}
	resolvedMismatch := resolver.ResolveForPod(mismatchPod)
	// RoleBindings in default namespace should NOT match, and ClusterRoleBinding subject specifies namespace "default"
	// so it should also not match. Total resolved roles must be 0.
	if len(resolvedMismatch) != 0 {
		t.Fatalf("expected 0 resolved roles due to namespace mismatch, got %d", len(resolvedMismatch))
	}

	// Test case 3: Default ServiceAccount if omitted
	defaultSAPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{ServiceAccountName: ""}, // default SA
	}
	resolvedDefault := resolver.ResolveForPod(defaultSAPod)
	if len(resolvedDefault) != 0 {
		t.Errorf("expected 0 resolved roles for default SA (no bindings configured for default), got %d", len(resolvedDefault))
	}

	// Test case 4: ClusterRoleBinding subject with empty namespace (matches any namespace)
	clusterBindingsWildcard := []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-binding-sa-wildcard"},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "test-sa",
					Namespace: "", // empty namespace -> matches any namespace
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "cluster-role",
			},
		},
	}
	resolverWildcard := NewResolver(roles, clusterRoles, nil, clusterBindingsWildcard)
	resolvedWildcard := resolverWildcard.ResolveForPod(mismatchPod)
	if len(resolvedWildcard) != 1 {
		t.Fatalf("expected 1 resolved role from wildcard cluster binding, got %d", len(resolvedWildcard))
	}
	if resolvedWildcard[0].Scope != model.ScopeCluster || resolvedWildcard[0].Source != "cluster-role" {
		t.Errorf("expected cluster binding, got source=%s scope=%v", resolvedWildcard[0].Source, resolvedWildcard[0].Scope)
	}
}
