// Package transport provides the mTLS HTTP client and WebSocket client
// used to communicate with the AI One API.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// ClientConfig holds the TLS material and retry policy.
type ClientConfig struct {
	BaseURL            string
	Cert               tls.Certificate
	CACertPool         *x509.CertPool
	InsecureSkipVerify bool
	Timeout            time.Duration
	RetryMax           int
	RetryDelay         time.Duration
}

// Client is a mTLS-capable HTTP client with retry logic.
type Client struct {
	cfg     ClientConfig
	http    *http.Client
	agentID string
	version string
}

// NewClient creates an mTLS HTTP client. caCertPool may be nil to use
// the system roots; cert may be the zero value before registration.
func NewClient(cfg ClientConfig) *Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // controlled by operator config
		RootCAs:            cfg.CACertPool,
	}
	// Only attach client cert if we have one (post-registration).
	if cfg.Cert.Certificate != nil {
		tlsCfg.Certificates = []tls.Certificate{cfg.Cert}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}

	return &Client{
		cfg: cfg,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
	}
}

// SetIdentity attaches agent identity headers to every request.
func (c *Client) SetIdentity(agentID, version string) {
	c.agentID = agentID
	c.version = version
}

// UpdateTLS replaces the TLS material (used after registration to upgrade
// from unauthenticated to mTLS).
func (c *Client) UpdateTLS(cert tls.Certificate, caPool *x509.CertPool) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: c.cfg.InsecureSkipVerify, //nolint:gosec
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
	}
	c.http.Transport = &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	c.cfg.Cert = cert
	c.cfg.CACertPool = caPool
}

// Do executes an HTTP request with retries on transient failures.
func (c *Client) Do(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request body: %w", err)
		}
		bodyBytes = b
	}

	var (
		resp *http.Response
		err  error
	)

	for attempt := 0; attempt <= c.cfg.RetryMax; attempt++ {
		if attempt > 0 {
			log.Debug().
				Str("method", method).
				Str("path", path).
				Int("attempt", attempt).
				Msg("retrying request")

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.cfg.RetryDelay * time.Duration(attempt)):
			}
		}

		resp, err = c.doOnce(ctx, method, path, bodyBytes)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		// Don't retry on client errors (4xx) — they won't resolve on retry.
		if err == nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, nil
		}
	}

	if err != nil {
		return nil, fmt.Errorf("request %s %s after %d attempts: %w", method, path, c.cfg.RetryMax+1, err)
	}
	return resp, nil
}

func (c *Client) doOnce(ctx context.Context, method, path string, bodyBytes []byte) (*http.Response, error) {
	url := c.cfg.BaseURL + path

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Agent-Version", c.version)
	if c.agentID != "" {
		req.Header.Set("X-Agent-ID", c.agentID)
	}

	return c.http.Do(req)
}

// PostJSON sends a POST with JSON body and decodes the JSON response into dst.
func (c *Client) PostJSON(ctx context.Context, path string, body, dst interface{}) error {
	resp, err := c.Do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, path, string(data))
	}

	if dst == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// GetJSON sends a GET and decodes the JSON response into dst.
func (c *Client) GetJSON(ctx context.Context, path string, dst interface{}) error {
	resp, err := c.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, path, string(data))
	}

	return json.NewDecoder(resp.Body).Decode(dst)
}
