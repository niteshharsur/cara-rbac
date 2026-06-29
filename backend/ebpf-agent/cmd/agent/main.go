package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Event mirrors the eBPF event struct.
// Must be kept in sync with cara_connect.bpf.c.
type Event struct {
	PID      uint32
	TID      uint32
	UID      uint32
	GID      uint32
	CgroupID uint64
	DAddr    uint32 // IPv4 in network byte order
	DPort    uint16
	Comm     [16]byte
}

// RuntimeEvent is the JSON payload sent to the runtime-monitor service.
type RuntimeEvent struct {
	ScanID    string `json:"scan_id"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Resource  string `json:"resource"`
	APIGroup  string `json:"api_group"`
	IsStartup bool   `json:"is_startup"`
}

// cgroupPodInfo holds pod metadata resolved from the cgroup path.
type cgroupPodInfo struct {
	PodName   string
	Namespace string
}

func main() {
	var (
		scanID      = flag.String("scan-id", "", "Scan UUID to tag events with (required)")
		monitorURL  = flag.String("monitor-url", "http://localhost:8080/api/v1/event", "Runtime monitor endpoint URL")
		startupSecs = flag.Int("startup-window", 120, "Seconds after container start to mark events as startup-only")
	)
	flag.Parse()

	if *scanID == "" {
		flag.Usage()
		os.Exit(1)
	}

	log.Printf("[ebpf-agent] starting  scan=%s  monitor=%s  startup-window=%ds",
		*scanID, *monitorURL, *startupSecs)

	// NOTE: In production, this agent uses cilium/ebpf or libbpfgo to:
	//   1. Load the compiled BPF object (cara_connect.bpf.o)
	//   2. Attach the kprobe to tcp_connect
	//   3. Poll the perf event ring buffer for Event structs
	//
	// Since eBPF loading requires Linux + root + kernel headers, this file
	// provides the event processing pipeline that would consume those events.
	// The BPF loading glue is stubbed with a comment below.

	log.Println("[ebpf-agent] NOTE: eBPF probe loading requires Linux kernel >= 5.8")
	log.Println("[ebpf-agent] In non-Linux environments, the agent runs in audit-log-only fallback mode")

	// Channel to receive decoded events (from eBPF perf buffer in production)
	eventCh := make(chan Event, 256)

	// Start the consumer goroutine
	containerStartTimes := make(map[uint64]time.Time) // cgroup_id -> first seen time
	startupWindow := time.Duration(*startupSecs) * time.Second

	go func() {
		client := &http.Client{Timeout: 5 * time.Second}

		for evt := range eventCh {
			// Resolve container metadata from cgroup ID
			podInfo := resolveCgroupToPod(evt.CgroupID)
			if podInfo == nil {
				continue
			}

			// Determine if this is a startup event
			now := time.Now()
			firstSeen, exists := containerStartTimes[evt.CgroupID]
			if !exists {
				containerStartTimes[evt.CgroupID] = now
				firstSeen = now
			}
			isStartup := now.Sub(firstSeen) < startupWindow

			// We don't know the exact verb/resource from a raw TCP connect.
			// In a full implementation, this would be paired with audit log
			// correlation or API server request parsing. Here we emit a
			// generic "api_access" event that the runtime-monitor can correlate
			// with the audit log stream.
			rtEvent := RuntimeEvent{
				ScanID:    *scanID,
				PodName:   podInfo.PodName,
				Namespace: podInfo.Namespace,
				Verb:      "connect",
				Resource:  "apiserver",
				APIGroup:  "",
				IsStartup: isStartup,
			}

			body, _ := json.Marshal(rtEvent)
			resp, err := client.Post(*monitorURL, "application/json", bytes.NewReader(body))
			if err != nil {
				log.Printf("[ebpf-agent] failed to report event: %v", err)
				continue
			}
			resp.Body.Close()

			comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
			log.Printf("[ebpf-agent] event  pid=%d  comm=%s  pod=%s/%s  dst=%s:%d  startup=%v",
				evt.PID, comm, podInfo.Namespace, podInfo.PodName,
				intToIP(evt.DAddr), evt.DPort, isStartup)
		}
	}()

	// ── eBPF loading stub ────────────────────────────────────────────────────
	// In production on Linux, replace this block with:
	//
	//   spec, err := ebpf.LoadCollectionSpec("bpf/cara_connect.bpf.o")
	//   coll, err := ebpf.NewCollection(spec)
	//   kp, err := link.Kprobe("tcp_connect", coll.Programs["trace_tcp_connect"])
	//   rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*64)
	//
	//   for {
	//       record, err := rd.Read()
	//       var evt Event
	//       binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt)
	//       eventCh <- evt
	//   }
	//
	log.Println("[ebpf-agent] eBPF probe load skipped (non-Linux or unprivileged)")
	log.Println("[ebpf-agent] waiting for signals (Ctrl+C to exit)...")

	// Wait for termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	close(eventCh)
	log.Println("[ebpf-agent] shutting down")
}

// resolveCgroupToPod reads /proc/<pid>/cgroup to extract the pod UID and
// then queries the kubelet API or uses the downward API to map it to pod metadata.
func resolveCgroupToPod(cgroupID uint64) *cgroupPodInfo {
	// In production, this reads:
	//   /sys/fs/cgroup/unified/<cgroup_path>
	// and extracts the pod UID from paths like:
	//   /kubepods/burstable/pod<uid>/<container_id>
	//
	// Then queries kubelet at localhost:10250/pods or uses a shared informer
	// cache to resolve pod name and namespace.
	//
	// Stub: return nil (no resolution in non-Linux mode)
	return nil
}

// intToIP converts a uint32 (network byte order) to a dotted-decimal IP string.
func intToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}

// Ensure Event struct size matches C struct (compile-time check)
var _ = [1]struct{}{}[unsafe.Sizeof(Event{})-48]
