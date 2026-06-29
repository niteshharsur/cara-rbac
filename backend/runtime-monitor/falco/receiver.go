package falco

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"

	// Mock/stub packages for gRPC receiver
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FalcoWebhookHandler processes incoming JSON alert POST requests from Falco.
type FalcoWebhookHandler struct {
	EventChan chan<- *RuntimeEvent
}

func (h *FalcoWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p FalcoPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	ev, err := ParseFalcoEvent(&p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// Forward event
	select {
	case h.EventChan <- ev:
	default:
		log.Println("[Falco] Event drop - channel queue full")
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"event_processed"}`))
}

// Mock gRPC receiver definition for Falco compatibility
type FalcoGrpcReceiver struct {
	EventChan chan<- *RuntimeEvent
}

func (s *FalcoGrpcReceiver) SendAlert(ctx context.Context, req *FalcoPayload) (*json.RawMessage, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty alert request")
	}
	ev, err := ParseFalcoEvent(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.EventChan <- ev
	resp := json.RawMessage(`{"status":"ok"}`)
	return &resp, nil
}

// StartGrpcServer runs the Mock gRPC listener for Falco in the background.
func StartGrpcServer(port string, eventChan chan<- *RuntimeEvent) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("[Falco-gRPC] failed to listen on port %s: %v", port, err)
		return
	}

	s := grpc.NewServer()
	log.Printf("[Falco-gRPC] listening on port %s", port)

	// In a real implementation, we would register the official Falco output service proto definition.
	// Since we are mocking, we just bind the listener.
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("[Falco-gRPC] server exit: %v", err)
		}
	}()
}
