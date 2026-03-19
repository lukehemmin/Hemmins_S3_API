package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// State holds the server's readiness state.
// The zero value is not ready.
type State struct {
	ready atomic.Bool
}

// NewState creates a new State. Readiness defaults to false (not ready).
func NewState() *State {
	return &State{}
}

// SetReady updates the readiness state.
func (s *State) SetReady(ready bool) {
	s.ready.Store(ready)
}

// IsReady reports whether the server is ready to serve requests.
func (s *State) IsReady() bool {
	return s.ready.Load()
}

// HealthzHandler returns 200 OK as long as the HTTP server process is running.
// It does NOT check database availability or bootstrap state.
// Used by container orchestrators for liveness probes.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ReadyzHandler returns 200 OK when the server is fully ready to handle requests.
// Returns 503 Service Unavailable when setup is required or the server is initializing.
// Used for readiness probes (e.g. docker-compose healthcheck, load balancer).
func ReadyzHandler(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !state.IsReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "not ready",
				"reason": "setup required or service initializing",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
