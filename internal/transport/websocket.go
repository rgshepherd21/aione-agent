// Package transport — websocket.go
// WSClient maintains a persistent, authenticated WebSocket connection to the
// AI One platform. It reconnects automatically using exponential backoff and
// dispatches inbound messages to registered handler functions.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	wsWriteTimeout = 10 * time.Second
	wsPingInterval = 30 * time.Second
	wsReadLimit    = 4 << 20 // 4 MB
)

// WSMessage is the envelope for all WebSocket messages.
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// WSHandler processes an inbound message. The returned error is logged but
// does not terminate the connection.
type WSHandler func(msg WSMessage) error

// WSClient manages a reconnecting, authenticated WebSocket connection to the
// AI One API. Register handlers with Handle before calling Run.
type WSClient struct {
	url     string
	agentID string
	version string

	mu       sync.RWMutex
	tlsCfg   *tls.Config
	handlers map[string]WSHandler
	conn     *websocket.Conn
	outbox   chan []byte // serialised WSMessage frames
}

// NewWSClient constructs a WSClient. tlsCfg may be nil before registration
// (connection will use system roots). Call Run to start the connection loop.
func NewWSClient(url string, tlsCfg *tls.Config, agentID, version string) *WSClient {
	return &WSClient{
		url:      url,
		tlsCfg:   tlsCfg,
		agentID:  agentID,
		version:  version,
		handlers: make(map[string]WSHandler),
		outbox:   make(chan []byte, 512),
	}
}

// NewTLSConfig builds a *tls.Config from cert + CA pool, suitable for passing
// to NewWSClient or updating an existing client via UpdateTLS.
func NewTLSConfig(cert tls.Certificate, caPool *x509.CertPool, insecure bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		RootCAs:            caPool,
		InsecureSkipVerify: insecure, //nolint:gosec // operator-controlled
	}
	if cert.Certificate != nil {
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

// UpdateTLS atomically replaces the TLS configuration, e.g. after a
// certificate rotation. Takes effect on the next reconnection.
func (c *WSClient) UpdateTLS(tlsCfg *tls.Config) {
	c.mu.Lock()
	c.tlsCfg = tlsCfg
	c.mu.Unlock()
}

// Handle registers a handler for the given message type.
// Safe to call from any goroutine before or after Run.
func (c *WSClient) Handle(msgType string, fn WSHandler) {
	c.mu.Lock()
	c.handlers[msgType] = fn
	c.mu.Unlock()
}

// Send serialises payload as JSON and enqueues the message for delivery.
// Returns an error only if the outbox is full (512 messages).
func (c *WSClient) Send(msgType string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling payload for %s: %w", msgType, err)
	}
	frame, err := json.Marshal(WSMessage{Type: msgType, Payload: data})
	if err != nil {
		return fmt.Errorf("marshalling ws envelope: %w", err)
	}
	select {
	case c.outbox <- frame:
		return nil
	default:
		return fmt.Errorf("ws outbox full, dropping %s message", msgType)
	}
}

// IsConnected reports whether a connection is currently active.
func (c *WSClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}

// Run connects (and reconnects on failure) until ctx is cancelled.
// Reconnect uses exponential back-off up to 60 s.
func (c *WSClient) Run(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if err := c.runSession(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Dur("retry_in", backoff).Msg("ws disconnected, reconnecting")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// runSession establishes one WebSocket session and runs until it closes.
func (c *WSClient) runSession(ctx context.Context) error {
	c.mu.RLock()
	tlsCfg := c.tlsCfg
	c.mu.RUnlock()

	header := http.Header{
		"X-Agent-ID":      {c.agentID},
		"X-Agent-Version": {c.version},
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.DialContext(ctx, c.url, header)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("ws dial (HTTP %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("ws dial: %w", err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	conn.SetReadLimit(wsReadLimit)
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPingInterval * 2))
	})

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
		conn.WriteMessage( //nolint:errcheck
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		conn.Close()
		log.Info().Str("url", c.url).Msg("ws session closed")
	}()

	log.Info().Str("url", c.url).Msg("ws connected")

	writeErr := make(chan error, 1)

	// Writer goroutine — serialises writes and handles pings.
	pingTicker := time.NewTicker(wsPingInterval)
	go func() {
		defer pingTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				writeErr <- nil
				return
			case <-pingTicker.C:
				conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)) //nolint:errcheck
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					writeErr <- fmt.Errorf("ping: %w", err)
					return
				}
			case frame, ok := <-c.outbox:
				if !ok {
					writeErr <- nil
					return
				}
				conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)) //nolint:errcheck
				if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
					writeErr <- fmt.Errorf("write: %w", err)
					return
				}
			}
		}
	}()

	// Reader loop.
	for {
		conn.SetReadDeadline(time.Now().Add(wsPingInterval * 2)) //nolint:errcheck
		_, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			return fmt.Errorf("ws read: %w", err)
		}

		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Warn().Err(err).Msg("ignoring unparseable ws message")
			continue
		}

		c.mu.RLock()
		fn, ok := c.handlers[msg.Type]
		c.mu.RUnlock()

		if !ok {
			log.Debug().Str("type", msg.Type).Msg("no ws handler registered")
			continue
		}

		if err := fn(msg); err != nil {
			log.Error().Err(err).Str("type", msg.Type).Msg("ws handler error")
		}

		// Bail if the writer goroutine has died.
		select {
		case wErr := <-writeErr:
			if wErr != nil {
				return wErr
			}
			return nil
		default:
		}
	}
}
