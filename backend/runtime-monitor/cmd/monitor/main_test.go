package main

import (
	"testing"
)

func TestCleanPodName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Deployment suffix: -<8-10 hex>-<5 alphanumeric>
		{"my-app-79b8979fc-2tflm", "my-app"},
		{"api-server-5d4fd7d76f-abcde", "api-server"},
		{"worker-1234567890-aaaaa", "worker"},
		
		// Job / DaemonSet / StatefulSet suffix: -<5 alphanumeric>
		{"my-job-24xcl", "my-job"},
		{"db-cluster-0-abcde", "db-cluster-0"},
		
		// Simple name
		{"static-pod", "static-pod"},
		{"my-app", "my-app"},
	}

	for _, tc := range tests {
		actual := cleanPodName(tc.input)
		if actual != tc.expected {
			t.Errorf("cleanPodName(%q) = %q; expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestClusterScopedResources(t *testing.T) {
	tests := []struct {
		resource string
		expected string
	}{
		{"nodes", "cluster"},
		{"namespaces", "cluster"},
		{"persistentvolumes", "cluster"},
		{"pods", "namespace"},
		{"services", "namespace"},
		{"secrets", "namespace"},
		{"configmaps", "namespace"},
	}

	for _, tc := range tests {
		scope := "namespace"
		if clusterScopedResources[tc.resource] {
			scope = "cluster"
		}
		if scope != tc.expected {
			t.Errorf("expected scope of %s to be %s, got %s", tc.resource, tc.expected, scope)
		}
	}
}
