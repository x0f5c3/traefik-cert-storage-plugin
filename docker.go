package certstorage

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultDockerEndpoint is the default Docker Engine API endpoint.
const DefaultDockerEndpoint = "unix:///var/run/docker.sock"

// dockerClient is a minimal Docker Engine API client used to signal containers.
type dockerClient struct {
	baseURL string
	client  *http.Client
}

func newDockerClient(endpoint string) (*dockerClient, error) {
	if endpoint == "" {
		endpoint = DefaultDockerEndpoint
	}

	// The socket path is not parsed as a URL: it may be a Windows path (unix://C:\...\docker.sock).
	if strings.HasPrefix(endpoint, "unix://") {
		socket := strings.TrimPrefix(endpoint, "unix://")
		if socket == "" {
			return nil, fmt.Errorf("invalid docker endpoint %q: missing socket path", endpoint)
		}

		return newUnixDockerClient(socket), nil
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid docker endpoint %q: %w", endpoint, err)
	}

	switch u.Scheme {
	case "tcp", "http":
		return &dockerClient{
			baseURL: "http://" + u.Host,
			client:  &http.Client{Timeout: 30 * time.Second},
		}, nil

	case "https":
		return &dockerClient{
			baseURL: "https://" + u.Host,
			client:  &http.Client{Timeout: 30 * time.Second},
		}, nil

	default:
		return nil, fmt.Errorf("invalid docker endpoint %q: unsupported scheme %q", endpoint, u.Scheme)
	}
}

func newUnixDockerClient(socket string) *dockerClient {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}

	return &dockerClient{
		baseURL: "http://docker",
		client:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

// Signal sends signal to the container (name or ID).
func (d *dockerClient) Signal(ctx context.Context, container, signal string) error {
	endpoint := d.baseURL + "/containers/" + url.PathEscape(container) + "/kill?signal=" + url.QueryEscape(signal)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("signaling container %s: %w", container, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	return fmt.Errorf("signaling container %s: unexpected status %d: %s", container, resp.StatusCode, strings.TrimSpace(string(body)))
}
