package certstorage_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	certstorage "github.com/x0f5c3/traefik-cert-storage-plugin"
)

const (
	certV1 = "-----BEGIN CERTIFICATE-----\nV1\n-----END CERTIFICATE-----\n"
	keyV1  = "-----BEGIN PRIVATE KEY-----\nK1\n-----END PRIVATE KEY-----\n"
	certV2 = "-----BEGIN CERTIFICATE-----\nV2\n-----END CERTIFICATE-----\n"
	keyV2  = "-----BEGIN PRIVATE KEY-----\nK2\n-----END PRIVATE KEY-----\n"
)

type signalRequest struct {
	method string
	path   string
	signal string
}

func writeACME(t *testing.T, path, cert, key string) {
	t.Helper()

	content := map[string]interface{}{
		"le": map[string]interface{}{
			"Account": map[string]interface{}{"Email": "admin@example.com"},
			"Certificates": []interface{}{
				map[string]interface{}{
					"domain":      map[string]interface{}{"main": "example.com", "sans": []string{"www.example.com"}},
					"certificate": base64.StdEncoding.EncodeToString([]byte(cert)),
					"key":         base64.StdEncoding.EncodeToString([]byte(key)),
					"Store":       "default",
				},
			},
		},
	}

	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func startFakeDocker(t *testing.T) (string, chan signalRequest) {
	t.Helper()

	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(dir, "docker.sock")

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	requests := make(chan signalRequest, 10)

	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			requests <- signalRequest{method: req.Method, path: req.URL.Path, signal: req.URL.Query().Get("signal")}
			rw.WriteHeader(http.StatusNoContent)
		}),
	}

	go func() { _ = server.Serve(listener) }()

	t.Cleanup(func() {
		_ = server.Close()
		_ = os.RemoveAll(dir)
	})

	return "unix://" + socket, requests
}

func startProvider(t *testing.T, config *certstorage.Config) (*certstorage.Provider, chan json.Marshaler) {
	t.Helper()

	provider, err := certstorage.New(context.Background(), config, "test")
	if err != nil {
		t.Fatal(err)
	}

	if err = provider.Init(); err != nil {
		t.Fatal(err)
	}

	cfgChan := make(chan json.Marshaler, 10)

	if err = provider.Provide(cfgChan); err != nil {
		t.Fatal(err)
	}

	return provider, cfgChan
}

func waitConfig(t *testing.T, cfgChan chan json.Marshaler) map[string]interface{} {
	t.Helper()

	select {
	case data := <-cfgChan:
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}

		result := make(map[string]interface{})
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}

		return result

	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for configuration")
	}

	return nil
}

func assertSignal(t *testing.T, requests chan signalRequest) {
	t.Helper()

	select {
	case req := <-requests:
		if req.method != http.MethodPost || req.path != "/containers/web-1/kill" || req.signal != "SIGUSR1" {
			t.Errorf("unexpected signal request: %+v", req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for signal")
	}
}

func assertFile(t *testing.T, path, expected string, perm os.FileMode) {
	t.Helper()

	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != expected {
		t.Errorf("%s: got %q, want %q", path, string(content), expected)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != perm {
		t.Errorf("%s: got permissions %v, want %v", path, info.Mode().Perm(), perm)
	}
}

func publishedCertificates(t *testing.T, cfg map[string]interface{}) []interface{} {
	t.Helper()

	tlsCfg, ok := cfg["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing TLS configuration: %v", cfg)
	}

	certs, _ := tlsCfg["certificates"].([]interface{})

	return certs
}

func TestProvider_ExportAndRenewal(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	storagePath := filepath.Join(dir, "store", "certstorage.json")
	volume := filepath.Join(dir, "volumes", "web")

	writeACME(t, acmePath, certV1, keyV1)

	endpoint, requests := startFakeDocker(t)

	config := certstorage.CreateConfig()
	config.PollInterval = "50ms"
	config.StoragePath = storagePath
	config.ACMEStorage = acmePath
	config.PublishCertificates = true
	config.DockerEndpoint = endpoint
	config.Services = []certstorage.ServiceConfig{
		{Name: "web", Domain: "www.example.com", Path: volume, Container: "web-1", Signal: "SIGUSR1"},
		{Name: "unknown", Domain: "other.org", Path: filepath.Join(dir, "volumes", "unknown"), Container: "unknown-1"},
	}

	provider, cfgChan := startProvider(t, config)

	cfg := waitConfig(t, cfgChan)

	certs := publishedCertificates(t, cfg)
	if len(certs) != 1 {
		t.Fatalf("got %d published certificates, want 1", len(certs))
	}

	assertFile(t, filepath.Join(volume, "cert.pem"), certV1, 0o644)
	assertFile(t, filepath.Join(volume, "key.pem"), keyV1, 0o600)
	assertSignal(t, requests)

	if _, err := os.Stat(filepath.Join(dir, "volumes", "unknown")); !os.IsNotExist(err) {
		t.Errorf("no certificate should be exported for an unknown domain: %v", err)
	}

	// Renewal.
	writeACME(t, acmePath, certV2, keyV2)

	waitConfig(t, cfgChan)

	assertFile(t, filepath.Join(volume, "cert.pem"), certV2, 0o644)
	assertFile(t, filepath.Join(volume, "key.pem"), keyV2, 0o600)
	assertSignal(t, requests)

	if err := provider.Stop(); err != nil {
		t.Fatal(err)
	}

	assertPersisted(t, config, requests)
}

// assertPersisted checks that the certificate is still available without the ACME source,
// and that it is not exported (nor signaled) again since it did not change.
func assertPersisted(t *testing.T, config *certstorage.Config, requests chan signalRequest) {
	t.Helper()

	if err := os.Remove(config.ACMEStorage); err != nil {
		t.Fatal(err)
	}

	store, err := certstorage.OpenStore(config.StoragePath)
	if err != nil {
		t.Fatal(err)
	}

	rec := store.Get("example.com")
	if rec == nil || rec.Certificate != certV2 || rec.Key != keyV2 || rec.Resolver != "le" {
		t.Fatalf("unexpected stored certificate: %+v", rec)
	}

	provider, cfgChan := startProvider(t, config)

	cfg := waitConfig(t, cfgChan)
	if len(publishedCertificates(t, cfg)) != 1 {
		t.Fatal("the stored certificate should be published after restart")
	}

	if err := provider.Stop(); err != nil {
		t.Fatal(err)
	}

	select {
	case req := <-requests:
		t.Errorf("unexpected signal request: %+v", req)
	default:
	}
}

func TestProvider_ReexportMissingFiles(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	volume := filepath.Join(dir, "volume")

	writeACME(t, acmePath, certV1, keyV1)

	config := certstorage.CreateConfig()
	config.PollInterval = "50ms"
	config.StoragePath = filepath.Join(dir, "certstorage.json")
	config.ACMEStorage = acmePath
	config.Services = []certstorage.ServiceConfig{
		{Name: "web", Domain: "example.com", Path: volume, CertFile: "tls.crt", KeyFile: "tls.key"},
	}

	provider, cfgChan := startProvider(t, config)
	t.Cleanup(func() { _ = provider.Stop() })

	cfg := waitConfig(t, cfgChan)
	if len(publishedCertificates(t, cfg)) != 0 {
		t.Error("certificates must not be published by default")
	}

	assertFile(t, filepath.Join(volume, "tls.crt"), certV1, 0o644)

	if err := os.RemoveAll(volume); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !fileExists(filepath.Join(volume, "tls.key")) || !fileExists(filepath.Join(volume, "tls.crt")) {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for the certificate to be exported again")
		}
		time.Sleep(20 * time.Millisecond)
	}

	assertFile(t, filepath.Join(volume, "tls.crt"), certV1, 0o644)
	assertFile(t, filepath.Join(volume, "tls.key"), keyV1, 0o600)
}

func TestProvider_Init(t *testing.T) {
	dir := t.TempDir()

	testCases := []struct {
		desc     string
		services []certstorage.ServiceConfig
		endpoint string
		storage  string
		wantErr  bool
	}{
		{
			desc:    "no services",
			storage: filepath.Join(dir, "a.json"),
		},
		{
			desc:     "missing name",
			storage:  filepath.Join(dir, "b.json"),
			services: []certstorage.ServiceConfig{{Domain: "example.com", Path: dir}},
			wantErr:  true,
		},
		{
			desc:     "missing domain",
			storage:  filepath.Join(dir, "c.json"),
			services: []certstorage.ServiceConfig{{Name: "a", Path: dir}},
			wantErr:  true,
		},
		{
			desc:     "missing path",
			storage:  filepath.Join(dir, "d.json"),
			services: []certstorage.ServiceConfig{{Name: "a", Domain: "example.com"}},
			wantErr:  true,
		},
		{
			desc:    "duplicated name",
			storage: filepath.Join(dir, "e.json"),
			services: []certstorage.ServiceConfig{
				{Name: "a", Domain: "example.com", Path: dir},
				{Name: "a", Domain: "example.org", Path: dir},
			},
			wantErr: true,
		},
		{
			desc:     "same cert and key file",
			storage:  filepath.Join(dir, "f.json"),
			services: []certstorage.ServiceConfig{{Name: "a", Domain: "example.com", Path: dir, CertFile: "x.pem", KeyFile: "x.pem"}},
			wantErr:  true,
		},
		{
			desc:     "invalid docker endpoint",
			storage:  filepath.Join(dir, "g.json"),
			endpoint: "ftp://foo",
			services: []certstorage.ServiceConfig{{Name: "a", Domain: "example.com", Path: dir, Container: "a"}},
			wantErr:  true,
		},
		{
			desc:    "missing storage path",
			wantErr: true,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			config := certstorage.CreateConfig()
			config.StoragePath = test.storage
			config.Services = test.services
			if test.endpoint != "" {
				config.DockerEndpoint = test.endpoint
			}

			provider, err := certstorage.New(context.Background(), config, "test")
			if err != nil {
				t.Fatal(err)
			}

			err = provider.Init()
			if test.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestStore_Find(t *testing.T) {
	store, err := certstorage.OpenStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	store.Put(&certstorage.CertificateRecord{Main: "*.example.com", Certificate: "wildcard", Key: "k"})
	store.Put(&certstorage.CertificateRecord{Main: "example.com", SANs: []string{"api.example.com"}, Certificate: "exact", Key: "k"})

	testCases := []struct {
		domain   string
		expected string
	}{
		{domain: "example.com", expected: "exact"},
		{domain: "API.example.com", expected: "exact"},
		{domain: "www.example.com", expected: "wildcard"},
		{domain: "a.b.example.com"},
		{domain: "example.org"},
	}

	for _, test := range testCases {
		rec := store.Find(test.domain)

		var got string
		if rec != nil {
			got = rec.Certificate
		}

		if got != test.expected {
			t.Errorf("%s: got %q, want %q", test.domain, got, test.expected)
		}
	}

	if store.Put(&certstorage.CertificateRecord{Main: "example.com", SANs: []string{"api.example.com"}, Certificate: "exact", Key: "k"}) {
		t.Error("putting an identical certificate should not change the store")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
