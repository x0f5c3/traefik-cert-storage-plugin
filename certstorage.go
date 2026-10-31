// Package certstorage is a Traefik provider plugin that persists certificates in an embedded store
// and exports them to the services requesting them, signaling their containers on renewal.
package certstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/traefik/genconf/dynamic"
	"github.com/traefik/genconf/dynamic/tls"
)

const (
	defaultCertFile = "cert.pem"
	defaultKeyFile  = "key.pem"
	defaultSignal   = "SIGHUP"
)

// ServiceConfig describes a service requesting a certificate.
type ServiceConfig struct {
	// Name identifies the service.
	Name string `json:"name,omitempty"`
	// Domain is the domain the certificate must cover.
	Domain string `json:"domain,omitempty"`
	// Path is the directory (e.g. a volume shared with the service) where the certificate is written.
	Path string `json:"path,omitempty"`
	// CertFile is the certificate file name, relative to Path (default: cert.pem).
	CertFile string `json:"certFile,omitempty"`
	// KeyFile is the private key file name, relative to Path (default: key.pem).
	KeyFile string `json:"keyFile,omitempty"`
	// Container is the name or ID of the container to signal when the certificate is written (optional).
	Container string `json:"container,omitempty"`
	// Signal is the signal sent to the container (default: SIGHUP).
	Signal string `json:"signal,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	// PollInterval is the interval between two synchronizations.
	PollInterval string `json:"pollInterval,omitempty"`
	// StoragePath is the path of the embedded certificate store.
	StoragePath string `json:"storagePath,omitempty"`
	// ACMEStorage is the path of Traefik's ACME storage file (acme.json) used as certificate source (optional).
	ACMEStorage string `json:"acmeStorage,omitempty"`
	// Resolvers restricts the ACME resolvers whose certificates are imported (default: all).
	Resolvers []string `json:"resolvers,omitempty"`
	// PublishCertificates publishes the stored certificates in Traefik's dynamic TLS configuration.
	PublishCertificates bool `json:"publishCertificates,omitempty"`
	// DockerEndpoint is the Docker Engine API endpoint used to signal containers.
	DockerEndpoint string `json:"dockerEndpoint,omitempty"`
	// Services are the services requesting certificates.
	Services []ServiceConfig `json:"services,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		PollInterval:   "10s",
		StoragePath:    "/data/certstorage.json",
		DockerEndpoint: DefaultDockerEndpoint,
	}
}

// Provider a certificate storage provider plugin.
type Provider struct {
	name   string
	config *Config
	logger *log.Logger

	pollInterval time.Duration
	services     []ServiceConfig

	store  *Store
	docker *dockerClient

	cancel func()
	done   chan struct{}
}

// New creates a new Provider plugin.
func New(_ context.Context, config *Config, name string) (*Provider, error) {
	if config == nil {
		return nil, errors.New("missing configuration")
	}

	pi, err := time.ParseDuration(config.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid poll interval: %w", err)
	}

	services := make([]ServiceConfig, 0, len(config.Services))
	for _, svc := range config.Services {
		if svc.CertFile == "" {
			svc.CertFile = defaultCertFile
		}
		if svc.KeyFile == "" {
			svc.KeyFile = defaultKeyFile
		}
		if svc.Signal == "" {
			svc.Signal = defaultSignal
		}
		services = append(services, svc)
	}

	return &Provider{
		name:         name,
		config:       config,
		logger:       log.New(os.Stdout, "[certstorage:"+name+"] ", log.LstdFlags),
		pollInterval: pi,
		services:     services,
	}, nil
}

// Init the provider.
func (p *Provider) Init() error {
	if p.pollInterval <= 0 {
		return errors.New("poll interval must be greater than 0")
	}

	if err := p.validateServices(); err != nil {
		return err
	}

	store, err := OpenStore(p.config.StoragePath)
	if err != nil {
		return err
	}
	p.store = store

	for _, svc := range p.services {
		if svc.Container == "" {
			continue
		}

		p.docker, err = newDockerClient(p.config.DockerEndpoint)
		if err != nil {
			return err
		}
		break
	}

	return nil
}

func (p *Provider) validateServices() error {
	seen := make(map[string]bool, len(p.services))

	for i, svc := range p.services {
		if svc.Name == "" {
			return fmt.Errorf("service #%d: name is required", i)
		}
		if seen[svc.Name] {
			return fmt.Errorf("service %q: duplicated name", svc.Name)
		}
		seen[svc.Name] = true

		if svc.Domain == "" {
			return fmt.Errorf("service %q: domain is required", svc.Name)
		}
		if svc.Path == "" {
			return fmt.Errorf("service %q: path is required", svc.Name)
		}
		if svc.CertFile == svc.KeyFile {
			return fmt.Errorf("service %q: certFile and keyFile must be different", svc.Name)
		}
	}

	return nil
}

// Provide creates and send dynamic configuration.
func (p *Provider) Provide(cfgChan chan<- json.Marshaler) error {
	if p.store == nil {
		return errors.New("provider is not initialized")
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})

	go func() {
		defer close(p.done)
		defer func() {
			if err := recover(); err != nil {
				p.logger.Print(err)
			}
		}()

		p.loadConfiguration(ctx, cfgChan)
	}()

	return nil
}

func (p *Provider) loadConfiguration(ctx context.Context, cfgChan chan<- json.Marshaler) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	p.sync(ctx, cfgChan, true)

	for {
		select {
		case <-ticker.C:
			p.sync(ctx, cfgChan, false)

		case <-ctx.Done():
			return
		}
	}
}

// sync imports the certificates from the sources, exports them to the services,
// and sends the dynamic configuration when the stored certificates changed.
func (p *Provider) sync(ctx context.Context, cfgChan chan<- json.Marshaler, force bool) {
	changed := p.importCertificates()

	p.exportCertificates(ctx)

	if err := p.store.Save(); err != nil {
		p.logger.Printf("Unable to save the certificate store: %v", err)
	}

	if !force && !changed {
		return
	}

	var payload json.Marshaler = &dynamic.JSONPayload{Configuration: p.generateConfiguration()}

	select {
	case cfgChan <- payload:
	case <-ctx.Done():
	}
}

func (p *Provider) importCertificates() bool {
	if p.config.ACMEStorage == "" {
		return false
	}

	records, err := readACMEStorage(p.config.ACMEStorage, p.config.Resolvers)
	if err != nil {
		if !os.IsNotExist(err) {
			p.logger.Printf("Unable to read the ACME storage: %v", err)
		}
		return false
	}

	var changed bool
	for _, rec := range records {
		if p.store.Put(rec) {
			p.logger.Printf("Certificate for %s stored", rec.Main)
			changed = true
		}
	}

	return changed
}

func (p *Provider) exportCertificates(ctx context.Context) {
	for _, svc := range p.services {
		if err := p.exportService(ctx, svc); err != nil {
			p.logger.Printf("Service %s: %v", svc.Name, err)
		}
	}
}

func (p *Provider) exportService(ctx context.Context, svc ServiceConfig) error {
	rec := p.store.Find(svc.Domain)
	if rec == nil {
		return nil
	}

	certPath := filepath.Join(svc.Path, svc.CertFile)
	keyPath := filepath.Join(svc.Path, svc.KeyFile)

	if p.store.ExportedFingerprint(svc.Name) == rec.Fingerprint && fileExists(certPath) && fileExists(keyPath) {
		return nil
	}

	// The directory must be readable by the service, which may run as a different user.
	if err := os.MkdirAll(svc.Path, 0o755); err != nil { //nolint:gosec // See above.
		return fmt.Errorf("creating directory: %w", err)
	}

	if err := writeFileAtomic(keyPath, []byte(rec.Key), 0o600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	if err := writeFileAtomic(certPath, []byte(rec.Certificate), 0o644); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}

	p.store.SetExportedFingerprint(svc.Name, rec.Fingerprint)
	p.logger.Printf("Certificate for %s exported to %s", svc.Domain, svc.Path)

	if svc.Container == "" || p.docker == nil {
		return nil
	}

	if err := p.docker.Signal(ctx, svc.Container, svc.Signal); err != nil {
		return err
	}

	p.logger.Printf("Signal %s sent to container %s", svc.Signal, svc.Container)

	return nil
}

// Stop to stop the provider and the related go routines.
func (p *Provider) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}

	if p.done != nil {
		<-p.done
	}

	return nil
}

func (p *Provider) generateConfiguration() *dynamic.Configuration {
	configuration := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:           make(map[string]*dynamic.Router),
			Middlewares:       make(map[string]*dynamic.Middleware),
			Services:          make(map[string]*dynamic.Service),
			ServersTransports: make(map[string]*dynamic.ServersTransport),
		},
		TCP: &dynamic.TCPConfiguration{
			Routers:  make(map[string]*dynamic.TCPRouter),
			Services: make(map[string]*dynamic.TCPService),
		},
		TLS: &dynamic.TLSConfiguration{
			Stores:  make(map[string]tls.Store),
			Options: make(map[string]tls.Options),
		},
		UDP: &dynamic.UDPConfiguration{
			Routers:  make(map[string]*dynamic.UDPRouter),
			Services: make(map[string]*dynamic.UDPService),
		},
	}

	if !p.config.PublishCertificates {
		return configuration
	}

	for _, rec := range p.store.List() {
		configuration.TLS.Certificates = append(configuration.TLS.Certificates, &tls.CertAndStores{
			Certificate: tls.Certificate{
				CertFile: strings.TrimSpace(rec.Certificate),
				KeyFile:  strings.TrimSpace(rec.Key),
			},
		})
	}

	return configuration
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
