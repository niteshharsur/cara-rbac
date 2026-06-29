package auditwebhook

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// AuditEvent represents a Kubernetes audit log event (simplified).
// Full spec: https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
type AuditEvent struct {
	Level             string       `json:"level"`
	AuditID           string       `json:"auditID"`
	Stage             string       `json:"stage"`
	RequestURI        string       `json:"requestURI"`
	Verb              string       `json:"verb"`
	User              AuditUser    `json:"user"`
	SourceIPs         []string     `json:"sourceIPs"`
	ObjectRef         *ObjectRef   `json:"objectRef,omitempty"`
	ResponseStatus    *StatusInfo  `json:"responseStatus,omitempty"`
	RequestReceivedAt time.Time    `json:"requestReceivedTimestamp"`
}

type AuditUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type ObjectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	APIGroup    string `json:"apiGroup"`
	APIVersion  string `json:"apiVersion"`
	Subresource string `json:"subresource"`
}

type StatusInfo struct {
	Code int `json:"code"`
}

// AuditEventList is the wrapper for batch audit webhook delivery.
type AuditEventList struct {
	Items []AuditEvent `json:"items"`
}

// RuntimeEvent is the payload sent to the runtime-monitor.
type RuntimeEvent struct {
	ScanID    string `json:"scan_id"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Resource  string `json:"resource"`
	APIGroup  string `json:"api_group"`
	IsStartup bool   `json:"is_startup"`
}

// WebhookHandler receives Kubernetes audit log webhook events and forwards
// relevant ones (service-account-initiated API calls) to the runtime monitor.
type WebhookHandler struct {
	ScanID     string
	MonitorURL string
	Client     *http.Client
}

// NewWebhookHandler creates a new audit webhook handler.
func NewWebhookHandler(scanID, monitorURL string) *WebhookHandler {
	return &WebhookHandler{
		ScanID:     scanID,
		MonitorURL: monitorURL,
		Client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// ServeHTTP handles incoming audit webhook POST requests.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var eventList AuditEventList
	if err := json.Unmarshal(body, &eventList); err != nil {
		// Try parsing as a single event
		var single AuditEvent
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		eventList.Items = []AuditEvent{single}
	}

	forwarded := 0
	for _, evt := range eventList.Items {
		if h.shouldForward(evt) {
			h.forwardToMonitor(evt)
			forwarded++
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"received":  len(eventList.Items),
		"forwarded": forwarded,
	})
}

// shouldForward returns true if the audit event is from a ServiceAccount
// and targets an API resource (not internal system requests).
func (h *WebhookHandler) shouldForward(evt AuditEvent) bool {
	// Only process ResponseComplete or ResponseStarted stages
	if evt.Stage != "ResponseComplete" && evt.Stage != "ResponseStarted" {
		return false
	}

	// Must have an object reference
	if evt.ObjectRef == nil {
		return false
	}

	// Skip system-internal requests (health checks, leader election, etc.)
	if strings.HasPrefix(evt.RequestURI, "/healthz") ||
		strings.HasPrefix(evt.RequestURI, "/readyz") ||
		strings.HasPrefix(evt.RequestURI, "/livez") {
		return false
	}

	// Only forward service account requests (format: system:serviceaccount:<ns>:<name>)
	if !strings.HasPrefix(evt.User.Username, "system:serviceaccount:") {
		return false
	}

	// Skip successful GET requests to reduce volume (optional — remove for full coverage)
	// if evt.Verb == "get" && evt.ResponseStatus != nil && evt.ResponseStatus.Code < 300 {
	//     return false
	// }

	return true
}

// forwardToMonitor sends the audit event to the runtime-monitor.
func (h *WebhookHandler) forwardToMonitor(evt AuditEvent) {
	// Extract pod identity from the ServiceAccount username
	// Format: system:serviceaccount:<namespace>:<sa-name>
	parts := strings.Split(evt.User.Username, ":")
	namespace := ""
	podName := ""
	if len(parts) >= 4 {
		namespace = parts[2]
		podName = parts[3] // This is actually the SA name, not pod name
	}

	// Use ObjectRef namespace if available (more accurate)
	if evt.ObjectRef.Namespace != "" {
		namespace = evt.ObjectRef.Namespace
	}

	rtEvent := RuntimeEvent{
		ScanID:    h.ScanID,
		PodName:   podName,
		Namespace: namespace,
		Verb:      evt.Verb,
		Resource:  evt.ObjectRef.Resource,
		APIGroup:  evt.ObjectRef.APIGroup,
		IsStartup: false, // Audit logs don't have startup info; runtime-monitor handles this
	}

	body, _ := json.Marshal(rtEvent)
	resp, err := h.Client.Post(h.MonitorURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[audit-webhook] forward failed: %v", err)
		return
	}
	resp.Body.Close()
}
