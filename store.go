package certstorage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

const (
	certificatesPrefix = "certificates/"
	exportsPrefix      = "exports/"
)

// exportRecord is the state of the last export made for a service.
type exportRecord struct {
	Fingerprint string `json:"fingerprint"`
}

type storeData struct {
	Certificates map[string]*CertificateRecord
	// Exports maps a service name to the fingerprint of the last certificate exported for it.
	Exports map[string]string
}

// Store is the certificate store.
// The content is kept in memory and persisted in a key-value Backend (file, directory, Consul, ...).
type Store struct {
	mu      sync.Mutex
	backend Backend
	data    storeData
	loaded  bool
	// dirty contains the keys modified since the last save.
	dirty map[string]bool
}

// NewStore creates a store persisted in backend. Load must be called before using the store.
func NewStore(backend Backend) *Store {
	return &Store{
		backend: backend,
		data: storeData{
			Certificates: make(map[string]*CertificateRecord),
			Exports:      make(map[string]string),
		},
		dirty: make(map[string]bool),
	}
}

// OpenStore opens (or creates) the store persisted in the JSON file located at path.
func OpenStore(path string) (*Store, error) {
	backend, err := NewFileBackend(path)
	if err != nil {
		return nil, err
	}

	s := NewStore(backend)
	if err := s.Load(); err != nil {
		return nil, err
	}

	return s, nil
}

// Loaded reports whether the store content has been loaded from the backend.
func (s *Store) Loaded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loaded
}

// Load loads the store content from the backend.
func (s *Store) Load() error {
	entries, err := s.backend.Load()
	if err != nil {
		return fmt.Errorf("loading storage: %w", err)
	}

	data := storeData{
		Certificates: make(map[string]*CertificateRecord),
		Exports:      make(map[string]string),
	}

	for key, value := range entries {
		switch {
		case strings.HasPrefix(key, certificatesPrefix):
			rec := &CertificateRecord{}
			if err := json.Unmarshal(value, rec); err != nil {
				return fmt.Errorf("decoding %s: %w", key, err)
			}
			data.Certificates[strings.TrimPrefix(key, certificatesPrefix)] = rec

		case strings.HasPrefix(key, exportsPrefix):
			exp := &exportRecord{}
			if err := json.Unmarshal(value, exp); err != nil {
				return fmt.Errorf("decoding %s: %w", key, err)
			}
			data.Exports[strings.TrimPrefix(key, exportsPrefix)] = exp.Fingerprint
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.data = data
	s.dirty = make(map[string]bool)
	s.loaded = true

	return nil
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
	s.dirty[certificatesPrefix+key] = true

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
// When several certificates match, the one expiring last is returned.
func (s *Store) Find(domain string) *CertificateRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(strings.TrimSpace(domain))
	records := s.sortedLocked()

	if rec := latest(records, func(d string) bool { return strings.EqualFold(d, domain) }); rec != nil {
		return rec
	}

	return latest(records, func(d string) bool { return matchWildcard(strings.ToLower(d), domain) })
}

// latest returns the record expiring last among the records having a domain matching match.
// Records are expected to be sorted, the first one wins on ties.
func latest(records []*CertificateRecord, match func(string) bool) *CertificateRecord {
	var (
		best        *CertificateRecord
		bestExpires time.Time
	)

	for _, rec := range records {
		for _, d := range rec.Domains() {
			if !match(d) {
				continue
			}

			expires := notAfter(rec.Certificate)
			if best == nil || expires.After(bestExpires) {
				best, bestExpires = rec, expires
			}

			break
		}
	}

	return best
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
	s.dirty[exportsPrefix+service] = true
}

// Save persists the entries modified since the last save.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.dirty) == 0 {
		return nil
	}

	entries := make(map[string][]byte, len(s.dirty))
	for key := range s.dirty {
		// The values are marshaled with their concrete types: Yaegi does not marshal interpreted types wrapped in interface{}.
		var (
			raw []byte
			err error
		)
		if strings.HasPrefix(key, certificatesPrefix) {
			raw, err = json.Marshal(s.data.Certificates[strings.TrimPrefix(key, certificatesPrefix)])
		} else {
			raw, err = json.Marshal(&exportRecord{Fingerprint: s.data.Exports[strings.TrimPrefix(key, exportsPrefix)]})
		}
		if err != nil {
			return fmt.Errorf("encoding %s: %w", key, err)
		}
		entries[key] = raw
	}

	if err := s.backend.Store(entries); err != nil {
		return fmt.Errorf("writing storage: %w", err)
	}

	s.dirty = make(map[string]bool)

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
