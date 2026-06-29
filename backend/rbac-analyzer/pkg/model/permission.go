package model

import "encoding/json"

// Scope defines the blast radius of a permission tuple.
type Scope string

const (
	ScopeCluster          Scope = "cluster"
	ScopeNamespace        Scope = "namespace"
	ScopeResourceSpecific Scope = "resource-specific"
)

// PermissionTuple is the atomic unit of the formal model — a (verb, resource, apiGroup, scope) quad.
// It corresponds to a single expanded entry in P_req, P_static, P_runtime, or P_cluster.
type PermissionTuple struct {
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
	APIGroup string `json:"apiGroup"`
	Scope    Scope  `json:"scope"`

	// Provenance — which Role/ClusterRole + Binding produced this tuple (M1 only)
	SourceRole    string   `json:"sourceRole,omitempty"`
	SourceBinding string   `json:"sourceBinding,omitempty"`
	ResourceNames []string `json:"resourceNames,omitempty"` // non-empty ⟹ resource-specific scope
}

// Key returns a canonical string suitable for use as a map key or set member.
// The key does NOT include ResourceNames so that resource-specific tuples
// deduplicate correctly against their namespace/cluster counterparts.
func (p PermissionTuple) Key() string {
	b, _ := json.Marshal(struct {
		Verb     string `json:"v"`
		Resource string `json:"r"`
		APIGroup string `json:"a"`
		Scope    Scope  `json:"s"`
	}{p.Verb, p.Resource, p.APIGroup, p.Scope})
	return string(b)
}

// PodPermissionSet is P_req for a single pod — the complete set of permission tuples
// derived from its ServiceAccount's bound Roles and ClusterRoles.
type PodPermissionSet struct {
	PodName        string            `json:"podName"`
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"serviceAccount"`
	Tuples         []PermissionTuple `json:"tuples"`
}

// PermissionSetMap is a scan-level map from "<namespace>/<podName>" to its permission set.
type PermissionSetMap map[string]PodPermissionSet

// TupleSet is an unordered collection of unique permission tuples (used for set arithmetic).
type TupleSet map[string]PermissionTuple

// NewTupleSet builds a TupleSet from a slice.
func NewTupleSet(tuples []PermissionTuple) TupleSet {
	s := make(TupleSet, len(tuples))
	for _, t := range tuples {
		s[t.Key()] = t
	}
	return s
}

// Subtract returns (a \ b) — tuples in a that are NOT in b.
func (a TupleSet) Subtract(b TupleSet) TupleSet {
	result := make(TupleSet)
	for k, v := range a {
		if _, exists := b[k]; !exists {
			result[k] = v
		}
	}
	return result
}

// Intersect returns (a ∩ b) — tuples present in both sets.
func (a TupleSet) Intersect(b TupleSet) TupleSet {
	result := make(TupleSet)
	for k, v := range a {
		if _, exists := b[k]; exists {
			result[k] = v
		}
	}
	return result
}

// Union returns (a ∪ b).
func (a TupleSet) Union(b TupleSet) TupleSet {
	result := make(TupleSet, len(a)+len(b))
	for k, v := range a {
		result[k] = v
	}
	for k, v := range b {
		result[k] = v
	}
	return result
}

// Slice converts the set back to a sorted slice (stable output for YAML generation).
func (s TupleSet) Slice() []PermissionTuple {
	out := make([]PermissionTuple, 0, len(s))
	for _, v := range s {
		out = append(out, v)
	}
	return out
}
