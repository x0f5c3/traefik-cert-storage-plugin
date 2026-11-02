# Traefik Certificate Storage Plugin

[![Build Status](https://github.com/x0f5c3/traefik-cert-storage-plugin/workflows/Main/badge.svg?branch=master)](https://github.com/x0f5c3/traefik-cert-storage-plugin/actions)

A [Traefik](https://traefik.io) provider plugin that:

1. **Stores certificates** in a pluggable storage backend: a single JSON file (default), a directory (one file per entry), or [Consul KV](https://developer.hashicorp.com/consul/docs/dynamic-app-config/kv).
   Certificates are imported from Traefik's ACME storage (`acme.json`) on every poll, so every issuance and renewal is persisted.
2. **Exports certificates to the services requesting them**, e.g. by writing the certificate and private key into a volume shared with the service's container,
   either as a simple certificate/key pair or in the same layout as Let's Encrypt clients (`cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`).
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
      # Certificate store backend (see "Storage backends" below).
      storage:
        type: file
        path: /data/certstorage.json
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
          # Export format: pem (default) or letsencrypt (see "Export formats" below).
          format: pem
          # File names, relative to path (pem format only, defaults: cert.pem and key.pem).
          certFile: fullchain.pem
          keyFile: privkey.pem
          # Container (name or ID) to signal when the certificate is written (optional).
          container: mailserver
          # Signal sent to the container (default: SIGHUP).
          signal: SIGHUP
```

### Storage backends

| `storage.type`   | Options                                                                                                     | Description                                                                                                                                         |
|------------------|-------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `file` (default) | `path`: JSON file (default: `/data/certstorage.json`)                                                       | All entries in a single JSON document, written atomically.                                                                                          |
| `directory`      | `path`: directory                                                                                           | One JSON file per entry (`certificates/<domain>.json`, `exports/<service>.json`), each written atomically. Easy to inspect, back up, or sync.        |
| `consul`         | `endpoint` (default: `http://127.0.0.1:8500`), `prefix` (default: `traefik-certstorage`), `token` (optional) | Entries are stored in the Consul KV store (`<prefix>/certificates/<domain>`, `<prefix>/exports/<service>`), so several Traefik instances can share them. |

```yaml
providers:
  plugin:
    certstorage:
      storage:
        type: consul
        endpoint: http://consul:8500
        prefix: traefik-certstorage
        token: my-acl-token
```

The store is loaded on the first successful poll: if a remote backend is not reachable when Traefik starts, the plugin retries on every poll.
Files written by the `file` and `directory` backends have `0600` permissions as they contain private keys.

New backends can be added by implementing the `Backend` interface (`Load() (map[string][]byte, error)` and `Store(entries map[string][]byte) error`).

### Export formats

| `format`        | Files written in `path`                                                                                                                                                                                                                         |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pem` (default) | `certFile` (default `cert.pem`): the certificate chain as stored by Traefik; `keyFile` (default `key.pem`): the private key.                                                                                                                     |
| `letsencrypt`   | The same files as Let's Encrypt clients (certbot `live/<domain>/` directory): `cert.pem` (leaf certificate), `chain.pem` (intermediate certificates), `fullchain.pem` (leaf + intermediates), and `privkey.pem` (private key in PKCS#8 format). |

Services expecting certbot's layout can mount the volume so `path` matches their expected `/etc/letsencrypt/live/<domain>` directory, for example:

```yaml
      services:
        - name: mail
          domain: mail.example.com
          path: /exports/mail/live/mail.example.com
          format: letsencrypt
          container: mailserver
```

Notes:

- Certificates are written with `0644` permissions, private keys with `0600` permissions.
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
