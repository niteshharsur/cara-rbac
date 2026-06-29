package parser

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

var (
	codecs = serializer.NewCodecFactory(scheme.Scheme)
	decode = codecs.UniversalDeserializer().Decode
)

// ManifestSet holds all Kubernetes objects parsed from a source directory.
type ManifestSet struct {
	Pods           []corev1.Pod
	Deployments    []interface{} // appsv1.Deployment — stored as runtime.Object
	StatefulSets   []interface{}
	DaemonSets     []interface{}
	Jobs           []interface{}
	CronJobs       []interface{}
	Roles          []rbacv1.Role
	ClusterRoles   []rbacv1.ClusterRole
	RoleBindings   []rbacv1.RoleBinding
	ClusterBindings []rbacv1.ClusterRoleBinding
	ServiceAccounts []corev1.ServiceAccount
}

// LoadManifestSet walks a directory (recursively) and parses all .yaml/.yml files.
// Helm charts are pre-rendered before calling this function (see helm_renderer.go).
func LoadManifestSet(dir string) (*ManifestSet, error) {
	ms := &ManifestSet{}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		return parseMultiDoc(data, ms)
	})
	return ms, err
}

// LoadManifestSetFromBytes parses a single in-memory YAML blob (used for Helm output).
func LoadManifestSetFromBytes(data []byte) (*ManifestSet, error) {
	ms := &ManifestSet{}
	return ms, parseMultiDoc(data, ms)
}

// parseMultiDoc splits a multi-document YAML on `---` and decodes each document.
func parseMultiDoc(data []byte, ms *ManifestSet) error {
	reader := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var rawObj runtime.RawExtension
		if err := reader.Decode(&rawObj); err != nil {
			if err == io.EOF {
				break
			}
			// Unknown CRDs — skip gracefully with a warning
			continue
		}
		if rawObj.Raw == nil {
			continue
		}
		obj, gvk, err := decode(rawObj.Raw, nil, nil)
		if err != nil {
			// Unrecognised kind (e.g. custom CRD) — skip
			continue
		}
		bucketObject(obj, gvk.Kind, ms)
	}
	return nil
}

// bucketObject sorts a decoded runtime.Object into the correct ManifestSet bucket.
func bucketObject(obj runtime.Object, kind string, ms *ManifestSet) {
	switch kind {
	case "Pod":
		if pod, ok := obj.(*corev1.Pod); ok {
			ms.Pods = append(ms.Pods, *pod)
		}
	case "Role":
		if r, ok := obj.(*rbacv1.Role); ok {
			ms.Roles = append(ms.Roles, *r)
		}
	case "ClusterRole":
		if cr, ok := obj.(*rbacv1.ClusterRole); ok {
			ms.ClusterRoles = append(ms.ClusterRoles, *cr)
		}
	case "RoleBinding":
		if rb, ok := obj.(*rbacv1.RoleBinding); ok {
			ms.RoleBindings = append(ms.RoleBindings, *rb)
		}
	case "ClusterRoleBinding":
		if crb, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
			ms.ClusterBindings = append(ms.ClusterBindings, *crb)
		}
	case "ServiceAccount":
		if sa, ok := obj.(*corev1.ServiceAccount); ok {
			ms.ServiceAccounts = append(ms.ServiceAccounts, *sa)
		}
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		// Higher-level workloads — extract pod spec and treat as a pod
		if pod := extractPodFromWorkload(obj, kind); pod != nil {
			ms.Pods = append(ms.Pods, *pod)
		}
	}
}

// extractPodFromWorkload synthesises a Pod object from a higher-level workload's pod template.
func extractPodFromWorkload(obj runtime.Object, kind string) *corev1.Pod {
	// Use reflection-free type assertions for each kind
	switch kind {
	case "Deployment":
		if d, ok := obj.(*appsv1.Deployment); ok {
			return podFromTemplate(d.Name, d.Namespace, d.Spec.Template)
		}
	case "StatefulSet":
		if s, ok := obj.(*appsv1.StatefulSet); ok {
			return podFromTemplate(s.Name, s.Namespace, s.Spec.Template)
		}
	case "DaemonSet":
		if d, ok := obj.(*appsv1.DaemonSet); ok {
			return podFromTemplate(d.Name, d.Namespace, d.Spec.Template)
		}
	case "Job":
		if j, ok := obj.(*batchv1.Job); ok {
			return podFromTemplate(j.Name, j.Namespace, j.Spec.Template)
		}
	case "CronJob":
		if c, ok := obj.(*batchv1.CronJob); ok {
			return podFromTemplate(c.Name, c.Namespace, c.Spec.JobTemplate.Spec.Template)
		}
	}
	return nil
}

// podFromTemplate builds a synthetic Pod for binding resolution purposes.
func podFromTemplate(name, ns string, tmpl corev1.PodTemplateSpec) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: tmpl.ObjectMeta,
		Spec:       tmpl.Spec,
	}
}

// ExtractPods returns all pods from the manifest set (already bucketed).
func (ms *ManifestSet) ExtractPods() []corev1.Pod { return ms.Pods }

// ExtractRoles returns a name-keyed map of namespace-scoped Roles.
func (ms *ManifestSet) ExtractRoles() map[string]rbacv1.Role {
	m := make(map[string]rbacv1.Role, len(ms.Roles))
	for _, r := range ms.Roles {
		key := r.Namespace + "/" + r.Name
		m[key] = r
	}
	return m
}

// ExtractClusterRoles returns a name-keyed map of ClusterRoles.
func (ms *ManifestSet) ExtractClusterRoles() map[string]rbacv1.ClusterRole {
	m := make(map[string]rbacv1.ClusterRole, len(ms.ClusterRoles))
	for _, cr := range ms.ClusterRoles {
		m[cr.Name] = cr
	}
	return m
}

// ExtractBindings returns all bindings (both Role and ClusterRole bindings).
func (ms *ManifestSet) ExtractBindings() ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding) {
	return ms.RoleBindings, ms.ClusterBindings
}
