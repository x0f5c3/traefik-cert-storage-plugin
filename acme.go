package certstorage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// acmeDomain mirrors the domain structure of Traefik's ACME storage.
type acmeDomain struct {
	Main string   `json:"main"`
	SANs []string `json:"sans"`
}

// acmeCertificate mirrors a certificate entry of Traefik's ACME storage.
type acmeCertificate struct {
	Domain      acmeDomain `json:"domain"`
	Certificate []byte     `json:"certificate"`
	Key         []byte     `json:"key"`
}

// acmeResolver mirrors a resolver entry of Traefik's ACME storage.
type acmeResolver struct {
	Certificates []acmeCertificate `json:"Certificates"` //nolint:tagliatelle // Traefik's ACME storage format.
}

// readACMEStorage reads the certificates contained in Traefik's ACME storage file (acme.json).
// If resolvers is not empty, only the certificates of these resolvers are returned.
func readACMEStorage(path string, resolvers []string) ([]*CertificateRecord, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	if len(raw) == 0 {
		return nil, nil
	}

	content := make(map[string]*acmeResolver)
	if err := json.Unmarshal(raw, &content); err != nil {
		return nil, fmt.Errorf("decoding ACME storage %s: %w", path, err)
	}

	var records []*CertificateRecord
	for _, name := range resolverNames(content, resolvers) {
		records = append(records, toRecords(name, content[name])...)
	}

	return records, nil
}

// resolverNames returns the sorted names of the resolvers to import.
func resolverNames(content map[string]*acmeResolver, resolvers []string) []string {
	allowed := make(map[string]bool, len(resolvers))
	for _, r := range resolvers {
		allowed[r] = true
	}

	names := make([]string, 0, len(content))
	for name, resolver := range content {
		if resolver == nil || (len(allowed) > 0 && !allowed[name]) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

func toRecords(name string, resolver *acmeResolver) []*CertificateRecord {
	records := make([]*CertificateRecord, 0, len(resolver.Certificates))
	for _, cert := range resolver.Certificates {
		if cert.Domain.Main == "" || len(cert.Certificate) == 0 || len(cert.Key) == 0 {
			continue
		}

		records = append(records, &CertificateRecord{
			Resolver:    name,
			Main:        cert.Domain.Main,
			SANs:        cert.Domain.SANs,
			Certificate: string(cert.Certificate),
			Key:         string(cert.Key),
		})
	}

	return records
}
