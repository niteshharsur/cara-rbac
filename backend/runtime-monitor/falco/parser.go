package falco

import (
	"errors"
	"log"
	"strings"
	"time"
)

// FalcoPayload represents the payload format from a Falco HTTP/gRPC alert output.
type FalcoPayload struct {
	Time   time.Time              `json:"time"`
	Rule   string                 `json:"rule"`
	Output string                 `json:"output"`
	Fields map[string]interface{} `json:"output_fields"`
}

// RuntimeEvent is the unified telemetry record mapped from Falco, eBPF, and Audit Logs.
type RuntimeEvent struct {
	ScanID         string    `json:"scan_id"`
	PodName        string    `json:"pod_name"`
	Namespace      string    `json:"namespace"`
	Verb           string    `json:"verb"`
	Resource       string    `json:"resource"`
	APIGroup       string    `json:"api_group"`
	ResponseCode   int       `json:"response_code"`
	Severity       string    `json:"severity"` // "high", "medium", "low"
	Source         string    `json:"source"`   // "falco", "ebpf", "audit"
	FirstObserved  time.Time `json:"first_observed"`
	LastObserved   time.Time `json:"last_observed"`
	ObservedCount  int       `json:"observed_count"`
}

// ParseFalcoEvent decodes a Falco payload into a unified RuntimeEvent.
func ParseFalcoEvent(p *FalcoPayload) (*RuntimeEvent, error) {
	if p == nil || p.Fields == nil {
		return nil, errors.New("empty or invalid Falco payload")
	}

	// 1. Resolve Namespace
	ns, _ := p.Fields["k8s.ns.name"].(string)
	if ns == "" {
		ns, _ = p.Fields["namespace"].(string)
	}
	if ns == "" {
		ns = "default" // fallback
	}

	// 2. Resolve Pod Name
	podName, _ := p.Fields["k8s.pod.name"].(string)
	if podName == "" {
		podName, _ = p.Fields["pod"].(string)
	}

	// 3. Resolve ServiceAccount / User
	username, _ := p.Fields["ka.user.name"].(string)
	saName := ""
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.Split(username, ":")
		if len(parts) >= 4 {
			saName = parts[3] // system:serviceaccount:<namespace>:<sa-name>
		}
	}
	if saName != "" {
		log.Printf("[Falco] Alert payload serviceaccount context: %s", saName)
	}

	// 4. Resolve Verb & Resource
	verb, _ := p.Fields["ka.verb"].(string)
	resource, _ := p.Fields["ka.target.resource"].(string)

	if verb == "" || resource == "" {
		return nil, errors.New("missing essential Kubernetes target attributes (verb/resource)")
	}

	// 5. Response Code
	respCode := 200
	if codeVal, ok := p.Fields["ka.response.code"]; ok {
		switch v := codeVal.(type) {
		case float64:
			respCode = int(v)
		case int:
			respCode = v
		}
	}

	// 6. Map Severity Based on Falco Rule or Resource Severity
	severity := "low"
	resLower := strings.ToLower(resource)
	verbLower := strings.ToLower(verb)
	if resLower == "secrets" || resLower == "clusterroles" || resLower == "clusterrolebindings" {
		severity = "high"
	} else if verbLower == "create" || verbLower == "delete" || verbLower == "patch" {
		severity = "medium"
	}

	return &RuntimeEvent{
		Namespace:    ns,
		PodName:      podName,
		Verb:         strings.ToLower(verb),
		Resource:     strings.ToLower(resource),
		ResponseCode: respCode,
		Severity:     severity,
		Source:       "falco",
		LastObserved: p.Time,
	}, nil
}
