package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"hyperdns/internal/dns"
)

type StreamHub struct {
	mu          sync.RWMutex
	clients     map[chan dns.QueryLogItem]struct{}
	history     []dns.QueryLogItem
	maxHistory  int
	inputChan   <-chan dns.QueryLogItem
}

func NewStreamHub(inputChan <-chan dns.QueryLogItem, maxHistory int) *StreamHub {
	if maxHistory <= 0 {
		maxHistory = 100
	}
	hub := &StreamHub{
		clients:    make(map[chan dns.QueryLogItem]struct{}),
		history:    make([]dns.QueryLogItem, 0, maxHistory),
		maxHistory: maxHistory,
		inputChan:  inputChan,
	}

	go hub.run()
	return hub
}

func (h *StreamHub) run() {
	for item := range h.inputChan {
		h.mu.Lock()
		// Append to circular history
		if len(h.history) >= h.maxHistory {
			h.history = append(h.history[1:], item)
		} else {
			h.history = append(h.history, item)
		}

		// Broadcast to all connected clients
		for ch := range h.clients {
			select {
			case ch <- item:
			default:
			}
		}
		h.mu.Unlock()
	}
}

func (h *StreamHub) GetRecentHistory() []dns.QueryLogItem {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]dns.QueryLogItem, len(h.history))
	copy(out, h.history)
	return out
}

func (h *StreamHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientChan := make(chan dns.QueryLogItem, 50)

	// Send initial history
	h.mu.Lock()
	h.clients[clientChan] = struct{}{}
	hist := make([]dns.QueryLogItem, len(h.history))
	copy(hist, h.history)
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, clientChan)
		h.mu.Unlock()
		close(clientChan)
	}()

	// Send history batch
	if histData, err := json.Marshal(hist); err == nil {
		_, _ = fmt.Fprintf(w, "event: history\ndata: %s\n\n", histData)
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-clientChan:
			if !ok {
				return
			}
			data, err := json.Marshal(item)
			if err == nil {
				_, _ = fmt.Fprintf(w, "event: query\ndata: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}
