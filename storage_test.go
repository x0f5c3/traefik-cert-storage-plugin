package certstorage_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	certstorage "github.com/x0f5c3/traefik-cert-storage-plugin"
)

type consulPair struct {
	Key   string `json:"Key"`   //nolint:tagliatelle // Consul API format.
	Value string `json:"Value"` //nolint:tagliatelle // Consul API format.
}

// fakeConsul is a minimal Consul KV HTTP API.
type fakeConsul struct {
	mu       sync.Mutex
	kv       map[string][]byte
	token    string
	failures int
}

func startFakeConsul(t *testing.T, token string, failures int) (*fakeConsul, string) {
	t.Helper()

	consul := &fakeConsul{kv: make(map[string][]byte), token: token, failures: failures}

	server := httptest.NewServer(consul)
	t.Cleanup(server.Close)

	return consul, server.URL
}

func (c *fakeConsul) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.failures > 0 {
		c.failures--
		http.Error(rw, "no cluster leader", http.StatusInternalServerError)
		return
	}

	if req.Header.Get("X-Consul-Token") != c.token {
		http.Error(rw, "ACL not found", http.StatusForbidden)
		return
	}

	key := strings.TrimPrefix(req.URL.Path, "/v1/kv/")

	switch req.Method {
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		c.kv[key] = body
		_, _ = rw.Write([]byte("true"))

	case http.MethodGet:
		if req.URL.Query().Get("recurse") == "" {
			http.Error(rw, "recurse expected", http.StatusBadRequest)
			return
		}

		var pairs []consulPair
		for k, v := range c.kv {
			if strings.HasPrefix(k, key) {
				pairs = append(pairs, consulPair{Key: k, Value: base64.StdEncoding.EncodeToString(v)})
			}
		}

		if len(pairs) == 0 {
			rw.WriteHeader(http.StatusNotFound)
			return
		}

		if err := json.NewEncoder(rw).Encode(pairs); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

	default:
		rw.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (c *fakeConsul) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]string, 0, len(c.kv))
	for k := range c.kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

func TestBackends(t *testing.T) {
	dir := t.TempDir()
	_, consulURL := startFakeConsul(t, "secret", 0)

	testCases := []struct {
		desc   string
		config certstorage.StorageConfig
	}{
		{desc: "file", config: certstorage.StorageConfig{Type: "file", Path: filepath.Join(dir, "file", "store.json")}},
		{desc: "directory", config: certstorage.StorageConfig{Type: "directory", Path: filepath.Join(dir, "directory")}},
		{desc: "consul", config: certstorage.StorageConfig{Type: "consul", Endpoint: consulURL, Prefix: "/certs/", Token: "secret"}},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			backend, err := certstorage.NewBackend(test.config)
			if err != nil {
				t.Fatal(err)
			}

			testStoreRoundTrip(t, backend)
		})
	}
}

func testStoreRoundTrip(t *testing.T, backend certstorage.Backend) {
	t.Helper()

	store := certstorage.NewStore(backend)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}

	if len(store.List()) != 0 {
		t.Fatal("the store should be empty")
	}

	store.Put(&certstorage.CertificateRecord{Main: "*.example.com", Certificate: "wildcard", Key: "k1"})
	store.Put(&certstorage.CertificateRecord{Main: "example.org", Certificate: "org", Key: "k2"})
	store.SetExportedFingerprint("..", "fp1")
	store.SetExportedFingerprint("web/api", "fp2")

	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	// Updates are merged with the existing entries.
	store.Put(&certstorage.CertificateRecord{Main: "example.org", Certificate: "org-renewed", Key: "k3"})

	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	assertReloaded(t, backend)
}

func assertReloaded(t *testing.T, backend certstorage.Backend) {
	t.Helper()

	reloaded := certstorage.NewStore(backend)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}

	if rec := reloaded.Find("www.example.com"); rec == nil || rec.Certificate != "wildcard" || rec.Key != "k1" {
		t.Errorf("unexpected wildcard certificate: %+v", rec)
	}

	if rec := reloaded.Get("example.org"); rec == nil || rec.Certificate != "org-renewed" || rec.Key != "k3" {
		t.Errorf("unexpected certificate: %+v", rec)
	}

	if fp := reloaded.ExportedFingerprint(".."); fp != "fp1" {
		t.Errorf("got fingerprint %q, want fp1", fp)
	}

	if fp := reloaded.ExportedFingerprint("web/api"); fp != "fp2" {
		t.Errorf("got fingerprint %q, want fp2", fp)
	}
}

func TestDirectoryBackend_Layout(t *testing.T) {
	dir := t.TempDir()

	backend, err := certstorage.NewDirectoryBackend(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = backend.Store(map[string][]byte{
		"certificates/*.example.com": []byte(`{}`),
		"exports/..":                 []byte(`{}`),
		"exports/a/b":                []byte(`{}`),
		"exports/.hidden":            []byte(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	var files []string
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("%s: got permissions %v, want 0600", rel, info.Mode().Perm())
		}

		files = append(files, filepath.ToSlash(rel))

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(files)

	expected := []string{
		"certificates/%2A.example.com.json",
		"exports/%2E%2E.json",
		"exports/%2Ehidden.json",
		"exports/a/b.json",
	}

	if strings.Join(files, ",") != strings.Join(expected, ",") {
		t.Errorf("got files %v, want %v", files, expected)
	}

	if err := backend.Store(map[string][]byte{"exports/": []byte(`{}`)}); err == nil {
		t.Error("an empty key segment should be rejected")
	}
}

func TestProvider_ConsulStorage(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")

	writeACME(t, acmePath, certV1, keyV1)

	// Consul is not available during the first attempts: the store must be loaded later.
	consul, consulURL := startFakeConsul(t, "", 2)

	config := certstorage.CreateConfig()
	config.PollInterval = "50ms"
	config.Storage = certstorage.StorageConfig{Type: "consul", Endpoint: consulURL}
	config.ACMEStorage = acmePath
	config.Services = []certstorage.ServiceConfig{
		{Name: "web", Domain: "example.com", Path: filepath.Join(dir, "volume")},
	}

	provider, cfgChan := startProvider(t, config)
	t.Cleanup(func() { _ = provider.Stop() })

	waitConfig(t, cfgChan)

	deadline := time.Now().Add(5 * time.Second)
	for len(consul.keys()) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for the store to be saved, got keys: %v", consul.keys())
		}
		time.Sleep(20 * time.Millisecond)
	}

	keys := consul.keys()
	if len(keys) != 2 || keys[0] != "traefik-certstorage/certificates/example.com" ||
		!strings.HasPrefix(keys[1], "traefik-certstorage/exports/web-") {
		t.Errorf("unexpected Consul keys: %v", keys)
	}

	assertFile(t, filepath.Join(dir, "volume", "cert.pem"), certV1, 0o644)
}

func TestStore_RefreshPreservesDirtyEntries(t *testing.T) {
	_, consulURL := startFakeConsul(t, "", 0)
	backend, err := certstorage.NewBackend(certstorage.StorageConfig{Type: "consul", Endpoint: consulURL})
	if err != nil {
		t.Fatal(err)
	}

	store := certstorage.NewStore(backend)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	store.Put(&certstorage.CertificateRecord{Main: "example.com", Certificate: certV1, Key: keyV1})
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	remoteBackend, err := certstorage.NewBackend(certstorage.StorageConfig{Type: "consul", Endpoint: consulURL})
	if err != nil {
		t.Fatal(err)
	}
	remoteStore := certstorage.NewStore(remoteBackend)
	if err := remoteStore.Load(); err != nil {
		t.Fatal(err)
	}
	remoteStore.Put(&certstorage.CertificateRecord{Main: "example.com", Certificate: certV2, Key: keyV2})
	remoteStore.Put(&certstorage.CertificateRecord{Main: "remote.example.com", Certificate: certV2, Key: keyV2})
	if err := remoteStore.Save(); err != nil {
		t.Fatal(err)
	}

	store.Put(&certstorage.CertificateRecord{Main: "example.com", Certificate: "local pending", Key: keyV2})
	changed, err := store.Refresh()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("refresh should report a remote certificate change")
	}
	if rec := store.Get("example.com"); rec == nil || rec.Certificate != "local pending" {
		t.Errorf("refresh discarded a pending local write: %+v", rec)
	}
	if rec := store.Get("remote.example.com"); rec == nil || rec.Certificate != certV2 {
		t.Errorf("refresh did not merge a remote certificate: %+v", rec)
	}

	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded := certstorage.NewStore(backend)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if rec := reloaded.Get("example.com"); rec == nil || rec.Certificate != "local pending" {
		t.Errorf("pending local write was not persisted after refresh: %+v", rec)
	}
}

func TestProvider_RefreshesRemoteCertificates(t *testing.T) {
	dir := t.TempDir()
	_, consulURL := startFakeConsul(t, "", 0)

	backend, err := certstorage.NewBackend(certstorage.StorageConfig{Type: "consul", Endpoint: consulURL})
	if err != nil {
		t.Fatal(err)
	}
	seed := certstorage.NewStore(backend)
	if err := seed.Load(); err != nil {
		t.Fatal(err)
	}
	seed.Put(&certstorage.CertificateRecord{Main: "example.com", Certificate: certV1, Key: keyV1})
	if err := seed.Save(); err != nil {
		t.Fatal(err)
	}

	config := certstorage.CreateConfig()
	config.PollInterval = "50ms"
	config.Storage = certstorage.StorageConfig{Type: "consul", Endpoint: consulURL}
	config.PublishCertificates = true
	config.Services = []certstorage.ServiceConfig{
		{Name: "web", Domain: "example.com", Path: filepath.Join(dir, "volume")},
	}

	provider, cfgChan := startProvider(t, config)
	t.Cleanup(func() { _ = provider.Stop() })
	waitConfig(t, cfgChan)
	assertFile(t, filepath.Join(dir, "volume", "cert.pem"), certV1, 0o644)

	updateBackend, err := certstorage.NewBackend(certstorage.StorageConfig{Type: "consul", Endpoint: consulURL})
	if err != nil {
		t.Fatal(err)
	}
	update := certstorage.NewStore(updateBackend)
	if err := update.Load(); err != nil {
		t.Fatal(err)
	}
	update.Put(&certstorage.CertificateRecord{Main: "example.com", Certificate: certV2, Key: keyV2})
	if err := update.Save(); err != nil {
		t.Fatal(err)
	}

	cfg := waitConfig(t, cfgChan)
	certificates := publishedCertificates(t, cfg)
	if len(certificates) != 1 {
		t.Fatalf("got %d published certificates, want 1", len(certificates))
	}
	published, ok := certificates[0].(map[string]interface{})
	if !ok || published["certFile"] != strings.TrimSpace(certV2) {
		t.Fatalf("published configuration did not contain the remote certificate update: %v", certificates[0])
	}
	assertFile(t, filepath.Join(dir, "volume", "cert.pem"), certV2, 0o644)
}

func TestProvider_DoesNotReplaceNewerRemoteCertificateWithACME(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	older := selfSigned(t, "example.com", time.Now().Add(24*time.Hour))
	newer := selfSigned(t, "example.com", time.Now().Add(90*24*time.Hour))
	writeACME(t, acmePath, older, keyV1)

	storage := certstorage.StorageConfig{Type: "consul"}
	_, consulURL := startFakeConsul(t, "", 0)
	storage.Endpoint = consulURL
	backend, err := certstorage.NewBackend(storage)
	if err != nil {
		t.Fatal(err)
	}
	seed := certstorage.NewStore(backend)
	if err := seed.Load(); err != nil {
		t.Fatal(err)
	}
	seed.Put(&certstorage.CertificateRecord{Main: "example.com", Certificate: newer, Key: keyV2})
	if err := seed.Save(); err != nil {
		t.Fatal(err)
	}

	config := certstorage.CreateConfig()
	config.PollInterval = "50ms"
	config.Storage = storage
	config.ACMEStorage = acmePath
	config.PublishCertificates = true
	provider, cfgChan := startProvider(t, config)
	t.Cleanup(func() { _ = provider.Stop() })

	cfg := waitConfig(t, cfgChan)
	certificates := publishedCertificates(t, cfg)
	if len(certificates) != 1 {
		t.Fatalf("got %d published certificates, want 1", len(certificates))
	}
	published, ok := certificates[0].(map[string]interface{})
	if !ok || published["certFile"] != strings.TrimSpace(newer) {
		t.Fatalf("published configuration did not retain the newer remote certificate: %v", certificates)
	}

	observer, err := certstorage.NewBackend(storage)
	if err != nil {
		t.Fatal(err)
	}
	reloaded := certstorage.NewStore(observer)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if rec := reloaded.Get("example.com"); rec == nil || rec.Certificate != newer {
		t.Errorf("the older ACME certificate replaced the newer remote certificate: %+v", rec)
	}
}

func TestProvider_ExportAcknowledgementsAreScopedToTarget(t *testing.T) {
	dir := t.TempDir()
	consul, consulURL := startFakeConsul(t, "", 0)
	failingEndpoint, failingRequests := startFakeDockerFailing(t, 1)
	successfulEndpoint, successfulRequests := startFakeDocker(t)
	volume := filepath.Join(dir, "volume")

	config := certstorage.CreateConfig()
	config.PollInterval = "1s"
	config.Storage = certstorage.StorageConfig{Type: "consul", Endpoint: consulURL}
	config.ACMEStorage = filepath.Join(dir, "acme.json")
	writeACME(t, config.ACMEStorage, certV1, keyV1)

	config.DockerEndpoint = failingEndpoint
	config.Services = []certstorage.ServiceConfig{
		{Name: "web", Domain: "example.com", Path: volume, Container: "web-1", Signal: "SIGUSR1"},
	}
	first, firstConfig := startProvider(t, config)
	waitConfig(t, firstConfig)
	assertSignal(t, failingRequests)
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}

	config.DockerEndpoint = successfulEndpoint
	config.Services[0].Container = "web-2"
	second, secondConfig := startProvider(t, config)
	waitConfig(t, secondConfig)
	assertSignalTo(t, successfulRequests, "web-2")
	if err := second.Stop(); err != nil {
		t.Fatal(err)
	}

	config.DockerEndpoint = failingEndpoint
	config.Services[0].Container = "web-1"
	restarted, restartedConfig := startProvider(t, config)
	waitConfig(t, restartedConfig)
	assertSignal(t, failingRequests)
	if err := restarted.Stop(); err != nil {
		t.Fatal(err)
	}

	if len(consul.keys()) == 0 {
		t.Error("expected the providers to persist their shared certificate and export state")
	}
}

func TestProvider_LetsEncryptFormat(t *testing.T) {
	dir := t.TempDir()
	acmePath := filepath.Join(dir, "acme.json")
	volume := filepath.Join(dir, "live", "example.com")

	leaf, issuer, key := generateChain(t, "example.com")

	ecKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	// Traefik stores the key as a SEC 1 "EC PRIVATE KEY".
	traefikKey := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKey}))

	writeACME(t, acmePath, leaf+issuer, traefikKey)

	config := certstorage.CreateConfig()
	config.PollInterval = "50ms"
	config.Storage.Path = filepath.Join(dir, "certstorage.json")
	config.ACMEStorage = acmePath
	config.Services = []certstorage.ServiceConfig{
		{Name: "web", Domain: "www.example.com", Path: volume, Format: "letsencrypt"},
	}

	provider, cfgChan := startProvider(t, config)
	t.Cleanup(func() { _ = provider.Stop() })

	waitConfig(t, cfgChan)

	assertFile(t, filepath.Join(volume, "cert.pem"), leaf, 0o644)
	assertFile(t, filepath.Join(volume, "chain.pem"), issuer, 0o644)
	assertFile(t, filepath.Join(volume, "fullchain.pem"), leaf+issuer, 0o644)

	raw, err := os.ReadFile(filepath.Clean(filepath.Join(volume, "privkey.pem")))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("privkey.pem should contain a PKCS#8 private key: %s", raw)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if !key.Equal(parsed) {
		t.Error("privkey.pem does not contain the certificate private key")
	}

	info, err := os.Stat(filepath.Join(volume, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("privkey.pem: got permissions %v, want 0600", info.Mode().Perm())
	}
}

// generateChain generates a leaf certificate signed by an intermediate CA, both PEM encoded, and the leaf private key.
func generateChain(t *testing.T, domain string) (string, string, *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain, "www." + domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	issuer := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	return leaf, issuer, key
}
