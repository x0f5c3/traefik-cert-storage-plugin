package certstorage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CertificateRecord is a certificate persisted in the store.
type CertificateRecord struct {
	Resolver    string    `json:"resolver,omitempty"`
	Main        string    `json:"main"`
	SANs        []string  `json:"sans,omitempty"`
	Certificate string    `json:"certificate"`
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Domains returns all the domains covered by the certificate.
func (r *CertificateRecord) Domains() []string {
	return append([]string{r.Main}, r.SANs...)
}

type storeData struct {
	Certificates map[string]*CertificateRecord `json:"certificates"`
	// Exports maps a service name to the fingerprint of the last certificate exported for it.
	Exports map[string]string `json:"exports"`
}

// Store is an embedded, file based, certificate store.
// The whole database is kept in memory and persisted atomically as a JSON document.
type Store struct {
	mu    sync.Mutex
	path  string
	data  storeData
	dirty bool
}

// OpenStore opens (or creates) the store located at path.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("storage path must not be empty")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating storage directory: %w", err)
	}

	s := &Store{
		path: path,
		data: storeData{
			Certificates: make(map[string]*CertificateRecord),
			Exports:      make(map[string]string),
		},
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading storage: %w", err)
	}

	if len(raw) == 0 {
		return s, nil
	}

	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("decoding storage %s: %w", path, err)
	}

	if s.data.Certificates == nil {
		s.data.Certificates = make(map[string]*CertificateRecord)
	}
	if s.data.Exports == nil {
		s.data.Exports = make(map[string]string)
	}

	return s, nil
}

// Put inserts or updates a certificate. It returns true if the store content changed.
func (s *Store) Put(rec *CertificateRecord) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec.Fingerprint = fingerprint(rec.Certificate, rec.Key)

	key := strings.ToLower(rec.Main)
	if existing, ok := s.data.Certificates[key]; ok &&
		existing.Fingerprint == rec.Fingerprint &&
		existing.Resolver == rec.Resolver &&
		strings.Join(existing.SANs, ",") == strings.Join(rec.SANs, ",") {
		return false
	}

	rec.UpdatedAt = time.Now().UTC()
	s.data.Certificates[key] = rec
	s.dirty = true

	return true
}

// Get returns the certificate whose main domain is main.
func (s *Store) Get(main string) *CertificateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.data.Certificates[strings.ToLower(main)]
}

// List returns all the certificates sorted by main domain.
func (s *Store) List() []*CertificateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.sortedLocked()
}

// Find returns the certificate covering domain.
// Exact matches (on the main domain or the SANs) take precedence over wildcard matches.
func (s *Store) Find(domain string) *CertificateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	records := s.sortedLocked()

	for _, rec := range records {
		for _, d := range rec.Domains() {
			if strings.EqualFold(d, domain) {
				return rec
			}
		}
	}

	for _, rec := range records {
		for _, d := range rec.Domains() {
			if matchWildcard(strings.ToLower(d), domain) {
				return rec
			}
		}
	}

	return nil
}

// ExportedFingerprint returns the fingerprint of the last certificate exported for service.
func (s *Store) ExportedFingerprint(service string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.data.Exports[service]
}

// SetExportedFingerprint records the fingerprint of the certificate exported for service.
func (s *Store) SetExportedFingerprint(service, fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data.Exports[service] == fp {
		return
	}

	s.data.Exports[service] = fp
	s.dirty = true
}

// Save persists the store if it has been modified.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty {
		return nil
	}

	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding storage: %w", err)
	}

	if err := writeFileAtomic(s.path, raw, 0o600); err != nil {
		return fmt.Errorf("writing storage: %w", err)
	}

	s.dirty = false

	return nil
}

func (s *Store) sortedLocked() []*CertificateRecord {
	keys := make([]string, 0, len(s.data.Certificates))
	for k := range s.data.Certificates {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	records := make([]*CertificateRecord, 0, len(keys))
	for _, k := range keys {
		records = append(records, s.data.Certificates[k])
	}

	return records
}

// matchWildcard reports whether the wildcard pattern (e.g. *.example.com) matches domain.
func matchWildcard(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	idx := strings.Index(domain, ".")
	if idx <= 0 {
		return false
	}

	return domain[idx+1:] == pattern[2:]
}

func fingerprint(cert, key string) string {
	sum := sha256.Sum256([]byte(cert + "\n" + key))
	return hex.EncodeToString(sum[:])
}

// writeFileAtomic writes data to a temporary file and renames it to path.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}

	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}

	return nil
}
