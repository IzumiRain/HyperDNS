package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

// Client is a storage-free control-plane client. It only dials the configured
// Unix socket when a method is invoked.
type Client struct {
	socketPath string
	httpClient *http.Client
}

func NewClient(socketPath string) *Client {
	return newClient(socketPath, (&net.Dialer{}).DialContext)
}

func newClient(socketPath string, dial dialContextFunc) *Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, "unix", socketPath)
		},
	}
	return newClientWithHTTP(socketPath, &http.Client{Transport: transport})
}

func newClientWithHTTP(socketPath string, httpClient *http.Client) *Client {
	return &Client{socketPath: socketPath, httpClient: httpClient}
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var out Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

func (c *Client) ListClients(ctx context.Context) ([]ClientView, error) {
	var out []ClientView
	err := c.do(ctx, http.MethodGet, "/v1/clients", nil, &out)
	return out, err
}

func (c *Client) CreateClient(ctx context.Context, in CreateClientRequest) (ClientView, error) {
	var out ClientView
	err := c.do(ctx, http.MethodPost, "/v1/clients", in, &out)
	return out, err
}

func (c *Client) DeleteClient(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/clients/"+id, nil, nil)
}

func (c *Client) FlushCache(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/cache/flush", struct{}{}, nil)
}

func (c *Client) StartBenchmark(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/benchmark", struct{}{}, nil)
}

func (c *Client) Settings(ctx context.Context) (SettingsView, error) {
	var out SettingsView
	err := c.do(ctx, http.MethodGet, "/v1/settings", nil, &out)
	return out, err
}

func (c *Client) RotateAPIKey(ctx context.Context, in RotateAPIKeyRequest) (RotateAPIKeyResult, error) {
	var out RotateAPIKeyResult
	err := c.do(ctx, http.MethodPost, "/v1/api-key/rotate", in, &out)
	return out, err
}

func (c *Client) PersistPanelPort(ctx context.Context, port int) error {
	return c.do(ctx, http.MethodPut, "/v1/settings/panel-port", PanelPortRequest{Port: port}, nil)
}

func (c *Client) ClearLockouts(ctx context.Context, in ClearLockoutsRequest) (int, error) {
	var out struct {
		Cleared int `json:"cleared"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/lockouts/clear", in, &out)
	return out.Cleared, err
}

func (c *Client) ChangeAdmin(ctx context.Context, in ChangeAdminRequest) error {
	return c.do(ctx, http.MethodPut, "/v1/admin/change", in, nil)
}

func (c *Client) ResetAdmin(ctx context.Context, in ResetAdminRequest) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/reset", in, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode control request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://hyperdns"+path, body)
	if err != nil {
		return fmt.Errorf("build control request: %w", err)
	}
	req.Header.Set(ProtocolVersionHeader, ProtocolVersion)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("control request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return decodeProtocolError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRequestBody)).Decode(out); err != nil {
		return fmt.Errorf("decode control response: %w", err)
	}
	return nil
}

func decodeProtocolError(resp *http.Response) error {
	var payload ErrorResponse
	err := json.NewDecoder(io.LimitReader(resp.Body, maxRequestBody)).Decode(&payload)
	if err != nil || payload.Error.Code == "" || payload.Error.Message == "" {
		return NewError(resp.StatusCode, "invalid_response", "control server returned an invalid error response", errors.New("invalid protocol error payload"))
	}
	return NewError(resp.StatusCode, payload.Error.Code, payload.Error.Message, nil)
}
