package falco

import (
	"testing"
	"time"
)

func TestParseFalcoEvent(t *testing.T) {
	// Sample Falco alert payload mimicking K8s API audit log event trigger
	p := &FalcoPayload{
		Time:   time.Now(),
		Rule:   "K8s Secret Exfiltration Alert",
		Output: "Kubernetes Secret exfiltrated by SA",
		Fields: map[string]interface{}{
			"k8s.ns.name":        "sample-app",
			"k8s.pod.name":       "api-server-79b",
			"ka.user.name":       "system:serviceaccount:sample-app:api-server-sa",
			"ka.verb":            "get",
			"ka.target.resource": "secrets",
			"ka.response.code":   float64(200),
		},
	}

	ev, err := ParseFalcoEvent(p)
	if err != nil {
		t.Fatalf("failed to parse event: %v", err)
	}

	if ev.Namespace != "sample-app" {
		t.Errorf("expected namespace sample-app, got %s", ev.Namespace)
	}
	if ev.PodName != "api-server-79b" {
		t.Errorf("expected pod name api-server-79b, got %s", ev.PodName)
	}
	if ev.Verb != "get" {
		t.Errorf("expected verb get, got %s", ev.Verb)
	}
	if ev.Resource != "secrets" {
		t.Errorf("expected resource secrets, got %s", ev.Resource)
	}
	if ev.ResponseCode != 200 {
		t.Errorf("expected response code 200, got %d", ev.ResponseCode)
	}
	if ev.Severity != "high" {
		t.Errorf("expected severity high, got %s", ev.Severity)
	}
}

func TestDeduplicator(t *testing.T) {
	d := NewDeduplicator(500 * time.Millisecond)

	sig := EventSignature("scan1", "ns1", "pod1", "get", "pods")

	if !d.ShouldProcess(sig) {
		t.Error("expected first event processing to be allowed")
	}

	if d.ShouldProcess(sig) {
		t.Error("expected duplicate event within window to be blocked")
	}

	// Wait for window to expire
	time.Sleep(600 * time.Millisecond)

	if !d.ShouldProcess(sig) {
		t.Error("expected event processing to be allowed after window expires")
	}
}
