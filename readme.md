# Traefik Certificate Storage Plugin

[![Build Status](https://github.com/x0f5c3/traefik-cert-storage-plugin/workflows/Main/badge.svg?branch=master)](https://github.com/x0f5c3/traefik-cert-storage-plugin/actions)

A [Traefik](https://traefik.io) provider plugin that:

1. **Stores certificates** in an embedded, file based store (a single JSON document written atomically, no external database needed).
   Certificates are imported from Traefik's ACME storage (`acme.json`) on every poll, so every issuance and renewal is persisted.
2. **Exports certificates to the services requesting them**, e.g. by writing the certificate and private key into a volume shared with the service's container.
   Every time the certificate is renewed, the files are updated the same way (they are also re-written if they disappear).
3. **Signals the service's container** (optional): after the files are written, a signal (default `SIGHUP`) is sent to the container through the Docker Engine API so that the service can reload its certificate.
4. Optionally **publishes the stored certificates** in Traefik's dynamic TLS configuration (`publishCertificates: true`).

The plugin only uses the Go standard library (plus [genconf](https://github.com/traefik/genconf)), so it runs in [Yaegi](https://github.com/traefik/yaegi), Traefik's embedded Go interpreter.

## Configuration

```yaml
# Static configuration

experimental:
  plugins:
    certstorage:
      moduleName: github.com/x0f5c3/traefik-cert-storage-plugin
      version: v0.1.0

certificatesResolvers:
  le:
    acme:
      email: admin@example.com
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web

providers:
  plugin:
    certstorage:
      # Interval between two synchronizations (default: 10s).
      pollInterval: 30s
      # Path of the embedded certificate store (default: /data/certstorage.json).
      storagePath: /data/certstorage.json
      # Traefik's ACME storage used as certificate source (optional).
      acmeStorage: /letsencrypt/acme.json
      # Only import the certificates of these resolvers (optional, default: all).
      resolvers:
        - le
      # Publish the stored certificates in Traefik's dynamic TLS configuration (default: false).
      publishCertificates: false
      # Docker Engine API endpoint used to signal containers (default: unix:///var/run/docker.sock).
      # Supported schemes: unix://, tcp://, http://, https://.
      dockerEndpoint: unix:///var/run/docker.sock
      # Services requesting a certificate.
      services:
        - name: mail
          # Domain the certificate must cover (main domain, SAN, or covered by a wildcard certificate).
          domain: mail.example.com
          # Directory where the certificate is written (e.g. a volume shared with the service).
          path: /exports/mail
          # File names, relative to path (defaults: cert.pem and key.pem).
          certFile: fullchain.pem
          keyFile: privkey.pem
          # Container (name or ID) to signal when the certificate is written (optional).
          container: mailserver
          # Signal sent to the container (default: SIGHUP).
          signal: SIGHUP
```

Notes:

- The certificate file contains the PEM certificate chain as stored by Traefik, and is written with `0644` permissions; the private key is written with `0600` permissions.
  The store itself is written with `0600` permissions as it contains private keys.
- A service is exported (and its container signaled) only when its certificate changed since the last export (the fingerprint of the last exported certificate is persisted in the store), or when the exported files are missing.
- The certificates stay in the store even if they disappear from the ACME storage.
- Signaling containers requires access to the Docker Engine API, e.g. by mounting `/var/run/docker.sock` into the Traefik container.

### Docker Compose example

```yaml
services:
  traefik:
    image: traefik:v3
    volumes:
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - letsencrypt:/letsencrypt
      - certstorage:/data
      - mail-certs:/exports/mail
      - /var/run/docker.sock:/var/run/docker.sock

  mailserver:
    container_name: mailserver
    image: my-mailserver
    volumes:
      - mail-certs:/etc/ssl/mail:ro

volumes:
  letsencrypt:
  certstorage:
  mail-certs:
```

## Development

```bash
make lint        # golangci-lint
make test        # go tests
make yaegi_test  # tests with the Yaegi interpreter
```

Plugin dependencies must be [vendored](https://golang.org/ref/mod#vendoring) (`make vendor`).
