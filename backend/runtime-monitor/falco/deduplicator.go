package falco

import (
	"sync"
	"time"
)

// Deduplicator keeps an in-memory sliding window cache of recent event signatures
// to filter out repetitive, redundant telemetry bursts from different agents (e.g. audit vs eBPF vs Falco).
type Deduplicator struct {
	mu      sync.Mutex
	history map[string]time.Time
	window  time.Duration
}

// NewDeduplicator creates a deduplication registry with a defined duration window.
func NewDeduplicator(window time.Duration) *Deduplicator {
	return &Deduplicator{
		history: make(map[string]time.Time),
		window:  window,
	}
}

// EventSignature computes a unique hash for deduplication.
func EventSignature(scanID, namespace, podName, verb, resource string) string {
	return scanID + "/" + namespace + "/" + podName + "/" + verb + "/" + resource
}

// ShouldProcess returns true if the event has not been processed within the sliding window.
func (d *Deduplicator) ShouldProcess(sig string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if lastProcessed, exists := d.history[sig]; exists {
		if now.Sub(lastProcessed) < d.window {
			return false // Deduplicate
		}
	}

	d.history[sig] = now
	return true
}

// CleanOldSignatures purges cache entries older than twice the deduplication window.
func (d *Deduplicator) CleanOldSignatures() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	limit := now.Add(-2 * d.window)
	for sig, t := range d.history {
		if t.Before(limit) {
			delete(d.history, sig)
		}
	}
}
