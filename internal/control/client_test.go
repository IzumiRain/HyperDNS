package control

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestClientConstructionIsLazyAndStatusUsesUnixSocket(t *testing.T) {
	var calls int
	var network, address string
	dial := func(_ context.Context, gotNetwork, gotAddress string) (net.Conn, error) {
		calls++
		network, address = gotNetwork, gotAddress
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			req, err := http.ReadRequest(bufio.NewReader(serverConn))
			if err != nil {
				return
			}
			if req.Header.Get(ProtocolVersionHeader) != ProtocolVersion {
				return
			}
			body := `{"total_queries":41,"cache_items":7}`
			_, _ = fmt.Fprintf(serverConn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}()
		return clientConn, nil
	}

	client := newClient("/private/control.sock", dial)
	if calls != 0 {
		t.Fatalf("constructor dialed %d times, want zero", calls)
	}
	got, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if calls != 1 || network != "unix" || address != "/private/control.sock" {
		t.Fatalf("dial = (%d, %q, %q), want (1, unix, socket path)", calls, network, address)
	}
	if got.TotalQueries != 41 || got.CacheItems != 7 {
		t.Fatalf("status = %+v", got)
	}
}

func TestClientMethodContract(t *testing.T) {
	tests := []struct {
		name, method, path string
		call               func(*Client) error
	}{
		{"list clients", http.MethodGet, "/v1/clients", func(c *Client) error { _, err := c.ListClients(context.Background()); return err }},
		{"create client", http.MethodPost, "/v1/clients", func(c *Client) error {
			_, err := c.CreateClient(context.Background(), CreateClientRequest{})
			return err
		}},
		{"delete client", http.MethodDelete, "/v1/clients/id-1", func(c *Client) error { return c.DeleteClient(context.Background(), "id-1") }},
		{"flush cache", http.MethodPost, "/v1/cache/flush", func(c *Client) error { return c.FlushCache(context.Background()) }},
		{"benchmark", http.MethodPost, "/v1/benchmark", func(c *Client) error { return c.StartBenchmark(context.Background()) }},
		{"settings", http.MethodGet, "/v1/settings", func(c *Client) error { _, err := c.Settings(context.Background()); return err }},
		{"rotate api key", http.MethodPost, "/v1/api-key/rotate", func(c *Client) error {
			_, err := c.RotateAPIKey(context.Background(), RotateAPIKeyRequest{})
			return err
		}},
		{"panel port", http.MethodPut, "/v1/settings/panel-port", func(c *Client) error { return c.PersistPanelPort(context.Background(), 9443) }},
		{"clear lockouts", http.MethodPost, "/v1/lockouts/clear", func(c *Client) error {
			_, err := c.ClearLockouts(context.Background(), ClearLockoutsRequest{})
			return err
		}},
		{"change admin", http.MethodPut, "/v1/admin/change", func(c *Client) error { return c.ChangeAdmin(context.Background(), ChangeAdminRequest{}) }},
		{"reset admin", http.MethodPost, "/v1/admin/reset", func(c *Client) error { return c.ResetAdmin(context.Background(), ResetAdminRequest{}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod, gotPath string
			client := newClientWithHTTP(DefaultSocketPath, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				gotMethod, gotPath = req.Method, req.URL.Path
				if req.Header.Get(ProtocolVersionHeader) != ProtocolVersion {
					t.Fatalf("version header = %q", req.Header.Get(ProtocolVersionHeader))
				}
				body := `{}`
				if tt.path == "/v1/clients" && tt.method == http.MethodGet {
					body = `[]`
				}
				return response(http.StatusOK, body), nil
			})})
			if err := tt.call(client); err != nil {
				t.Fatalf("call: %v", err)
			}
			if gotMethod != tt.method || gotPath != tt.path {
				t.Fatalf("request = %s %s, want %s %s", gotMethod, gotPath, tt.method, tt.path)
			}
		})
	}
}

func TestClientPropagatesTypedProtocolErrorWithoutSecretLeak(t *testing.T) {
	client := newClientWithHTTP(DefaultSocketPath, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusUnprocessableEntity, `{"error":{"code":"invalid_request","message":"request is invalid"}}`), nil
	})})

	_, err := client.CreateClient(context.Background(), CreateClientRequest{Name: "do-not-echo", Days: 1})
	opErr, ok := asError(err)
	if !ok {
		t.Fatalf("error = %T %v, want typed Error", err, err)
	}
	if opErr.Status != http.StatusUnprocessableEntity || opErr.Code != "invalid_request" || opErr.Message != "request is invalid" {
		t.Fatalf("error = %+v", opErr)
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("error leaked request value: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
