package parser

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// HelmRenderer renders a Helm chart to a ManifestSet using `helm template`.
// It requires the `helm` binary to be on PATH.
type HelmRenderer struct {
	// HelmBin is the path to the helm binary; defaults to "helm".
	HelmBin string
}

// NewHelmRenderer creates a renderer using the system helm binary.
func NewHelmRenderer() *HelmRenderer {
	bin := os.Getenv("HELM_BIN")
	if bin == "" {
		bin = "helm"
	}
	return &HelmRenderer{HelmBin: bin}
}

// IsHelmChart returns true if the given directory contains a Chart.yaml file.
func IsHelmChart(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "Chart.yaml"))
	return err == nil
}

// RenderChart runs `helm template` on the chart directory and returns the
// rendered YAML as a ManifestSet. valuesFiles are optional -f overrides.
func (r *HelmRenderer) RenderChart(chartDir string, releaseName string, namespace string, valuesFiles []string) (*ManifestSet, error) {
	// Check if helm binary exists on system PATH
	if _, err := exec.LookPath(r.HelmBin); err != nil {
		return nil, fmt.Errorf("helm binary %q not found on system PATH. Please install Helm (https://helm.sh) to enable chart ingestion: %w", r.HelmBin, err)
	}

	if releaseName == "" {
		releaseName = "cara-rbac-scan"
	}

	args := []string{"template", releaseName, chartDir, "--include-crds"}
	if namespace != "" {
		args = append(args, "--namespace", namespace)
	}
	for _, vf := range valuesFiles {
		args = append(args, "-f", vf)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(r.HelmBin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helm template execution failed: %w\nstderr: %s", err, stderr.String())
	}

	return LoadManifestSetFromBytes(stdout.Bytes())
}

// RenderUmbrellaChart recursively renders an umbrella chart and all its
// subcharts, merging the results into one ManifestSet.
func (r *HelmRenderer) RenderUmbrellaChart(chartDir string, releaseName string, namespace string, valuesFiles []string) (*ManifestSet, error) {
	// First render the parent chart itself
	ms, err := r.RenderChart(chartDir, releaseName, namespace, valuesFiles)
	if err != nil {
		return nil, err
	}

	// Walk charts/ subdirectory for subcharts
	chartsDir := filepath.Join(chartDir, "charts")
	entries, err := os.ReadDir(chartsDir)
	if os.IsNotExist(err) {
		return ms, nil // no subcharts
	}
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subChart := filepath.Join(chartsDir, e.Name())
		if !IsHelmChart(subChart) {
			continue
		}
		subRelease := releaseName + "-" + strings.ToLower(e.Name())
		subMS, err := r.RenderChart(subChart, subRelease, namespace, valuesFiles)
		if err != nil {
			// Non-fatal: log and continue
			fmt.Fprintf(os.Stderr, "[helm] sub-chart %s render failed: %v\n", e.Name(), err)
			continue
		}
		mergeManifestSets(ms, subMS)
	}
	return ms, nil
}

// mergeManifestSets appends all objects from src into dst.
func mergeManifestSets(dst, src *ManifestSet) {
	dst.Pods = append(dst.Pods, src.Pods...)
	dst.Roles = append(dst.Roles, src.Roles...)
	dst.ClusterRoles = append(dst.ClusterRoles, src.ClusterRoles...)
	dst.RoleBindings = append(dst.RoleBindings, src.RoleBindings...)
	dst.ClusterBindings = append(dst.ClusterBindings, src.ClusterBindings...)
	dst.ServiceAccounts = append(dst.ServiceAccounts, src.ServiceAccounts...)
}
