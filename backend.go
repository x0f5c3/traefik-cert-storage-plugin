package certstorage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Storage backend types.
const (
	StorageFile      = "file"
	StorageDirectory = "directory"
	StorageConsul    = "consul"
)

// Backend is a key-value storage backend.
// Keys are slash separated paths (e.g. certificates/example.com), values are JSON documents.
type Backend interface {
	// Load returns all the entries.
	Load() (map[string][]byte, error)
	// Store creates or updates the entries.
	Store(entries map[string][]byte) error
}

// StorageConfig is the storage backend configuration.
type StorageConfig struct {
	// Type is the backend type: file (default), directory, or consul.
	Type string `json:"type,omitempty"`
	// Path is the path of the JSON file (file) or of the directory (directory).
	Path string `json:"path,omitempty"`
	// Endpoint is the Consul HTTP API address (consul, default: http://127.0.0.1:8500).
	Endpoint string `json:"endpoint,omitempty"`
	// Prefix is the key prefix (consul, default: traefik-certstorage).
	Prefix string `json:"prefix,omitempty"`
	// Token is the Consul ACL token (consul, optional).
	Token string `json:"token,omitempty"`
}

// NewBackend creates the storage backend described by config.
func NewBackend(config StorageConfig) (Backend, error) { //nolint:ireturn // Factory of the configured backend.
	// The results are checked explicitly: Yaegi loses the error when forwarding (*T, error) as (Backend, error).
	switch config.Type {
	case "", StorageFile:
		backend, err := NewFileBackend(config.Path)
		if err != nil {
			return nil, err
		}
		return backend, nil

	case StorageDirectory:
		backend, err := NewDirectoryBackend(config.Path)
		if err != nil {
			return nil, err
		}
		return backend, nil

	case StorageConsul:
		backend, err := NewConsulBackend(config.Endpoint, config.Prefix, config.Token)
		if err != nil {
			return nil, err
		}
		return backend, nil

	default:
		return nil, fmt.Errorf("unsupported storage type %q", config.Type)
	}
}

func validateKey(key string) error {
	for _, segment := range strings.Split(key, "/") {
		if segment == "" {
			return fmt.Errorf("invalid storage key %q", key)
		}
	}

	return nil
}

// FileBackend stores all the entries in a single JSON document, written atomically.
type FileBackend struct {
	mu   sync.Mutex
	path string
}

// NewFileBackend creates a backend storing the entries in the JSON file located at path.
func NewFileBackend(path string) (*FileBackend, error) {
	if path == "" {
		return nil, errors.New("storage path must not be empty")
	}

	return &FileBackend{path: path}, nil
}

// Load returns all the entries.
func (b *FileBackend) Load() (map[string][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	content, err := b.read()
	if err != nil {
		return nil, err
	}

	entries := make(map[string][]byte, len(content))
	for k, v := range content {
		entries[k] = v
	}

	return entries, nil
}

// Store creates or updates the entries.
func (b *FileBackend) Store(entries map[string][]byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	content, err := b.read()
	if err != nil {
		return err
	}

	for k, v := range entries {
		content[k] = v
	}

	raw, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}

	return writeFileAtomic(b.path, raw, 0o600)
}

func (b *FileBackend) read() (map[string]json.RawMessage, error) {
	content := make(map[string]json.RawMessage)

	raw, err := os.ReadFile(filepath.Clean(b.path))
	if err != nil {
		if os.IsNotExist(err) {
			return content, nil
		}
		return nil, err
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return content, nil
	}

	if err := json.Unmarshal(raw, &content); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", b.path, err)
	}

	return content, nil
}

// DirectoryBackend stores each entry in its own file (<dir>/<key>.json), written atomically.
type DirectoryBackend struct {
	dir string
}

// NewDirectoryBackend creates a backend storing the entries as files in dir.
func NewDirectoryBackend(dir string) (*DirectoryBackend, error) {
	if dir == "" {
		return nil, errors.New("storage path must not be empty")
	}

	return &DirectoryBackend{dir: dir}, nil
}

// Load returns all the entries.
func (b *DirectoryBackend) Load() (map[string][]byte, error) {
	entries := make(map[string][]byte)

	err := filepath.WalkDir(b.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == b.dir {
				return fs.SkipDir
			}
			return err
		}

		if d.IsDir() || strings.HasPrefix(d.Name(), ".") || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		rel, err := filepath.Rel(b.dir, strings.TrimSuffix(path, ".json"))
		if err != nil {
			return err
		}

		segments := strings.Split(filepath.ToSlash(rel), "/")
		for i, segment := range segments {
			if segments[i], err = url.QueryUnescape(segment); err != nil {
				return fmt.Errorf("invalid storage file %s: %w", path, err)
			}
		}

		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return err
		}

		entries[strings.Join(segments, "/")] = raw

		return nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// Store creates or updates the entries.
func (b *DirectoryBackend) Store(entries map[string][]byte) error {
	for key, value := range entries {
		if err := validateKey(key); err != nil {
			return err
		}

		path := b.path(key)

		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}

		if err := writeFileAtomic(path, value, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func (b *DirectoryBackend) path(key string) string {
	segments := strings.Split(key, "/")
	for i, segment := range segments {
		segments[i] = escapeSegment(segment)
	}

	return filepath.Join(b.dir, filepath.Join(segments...)+".json")
}

// escapeSegment escapes a key segment so it can safely be used as a file name
// (no path separator, no "." or ".." names, no hidden files).
func escapeSegment(segment string) string {
	escaped := url.QueryEscape(segment)
	if strings.Trim(escaped, ".") == "" {
		return strings.ReplaceAll(escaped, ".", "%2E")
	}

	if strings.HasPrefix(escaped, ".") {
		return "%2E" + escaped[1:]
	}

	return escaped
}

// ConsulBackend stores the entries in the Consul KV store, using the HTTP API.
type ConsulBackend struct {
	endpoint string
	prefix   string
	token    string
	client   *http.Client
}

// NewConsulBackend creates a backend storing the entries in Consul under prefix.
func NewConsulBackend(endpoint, prefix, token string) (*ConsulBackend, error) {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8500"
	}

	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid consul endpoint %q", endpoint)
	}

	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		prefix = "traefik-certstorage"
	}

	return &ConsulBackend{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		prefix:   prefix,
		token:    token,
		client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

type consulPair struct {
	Key   string `json:"Key"`   //nolint:tagliatelle // Consul API format.
	Value string `json:"Value"` //nolint:tagliatelle // Consul API format.
}

// Load returns all the entries.
func (b *ConsulBackend) Load() (map[string][]byte, error) {
	resp, err := b.do(http.MethodGet, b.url(b.prefix+"/")+"?recurse=true", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	entries := make(map[string][]byte)

	if resp.StatusCode == http.StatusNotFound {
		return entries, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, consulError(resp)
	}

	var pairs []consulPair
	if err := json.NewDecoder(resp.Body).Decode(&pairs); err != nil {
		return nil, fmt.Errorf("decoding consul response: %w", err)
	}

	for _, pair := range pairs {
		key := strings.TrimPrefix(pair.Key, b.prefix+"/")
		if key == pair.Key || key == "" || pair.Value == "" {
			continue
		}

		value, err := base64.StdEncoding.DecodeString(pair.Value)
		if err != nil {
			return nil, fmt.Errorf("decoding consul key %s: %w", pair.Key, err)
		}

		entries[key] = value
	}

	return entries, nil
}

// Store creates or updates the entries.
func (b *ConsulBackend) Store(entries map[string][]byte) error {
	for key, value := range entries {
		if err := b.put(key, value); err != nil {
			return err
		}
	}

	return nil
}

func (b *ConsulBackend) put(key string, value []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}

	resp, err := b.do(http.MethodPut, b.url(b.prefix+"/"+key), value)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return consulError(resp)
	}

	return nil
}

func (b *ConsulBackend) url(key string) string {
	segments := strings.Split(key, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}

	return b.endpoint + "/v1/kv/" + strings.Join(segments, "/")
}

func (b *ConsulBackend) do(method, target string, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	if b.token != "" {
		req.Header.Set("X-Consul-Token", b.token)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consul request: %w", err)
	}

	// The body is read before the context is canceled.
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("consul request: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))

	return resp, nil
}

func consulError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("consul: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
