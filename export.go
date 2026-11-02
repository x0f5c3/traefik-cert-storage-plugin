package certstorage

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
)

const (
	publicPerm  os.FileMode = 0o644
	privatePerm os.FileMode = 0o600
)

// exportFile is a file written in the directory of a service.
type exportFile struct {
	name    string
	content string
	perm    os.FileMode
}

// exportFiles returns the files to write for svc.
// The private key is always written first, so a certificate is never exported without its key.
func exportFiles(svc ServiceConfig, rec *CertificateRecord) []exportFile {
	if svc.Format == FormatLetsEncrypt {
		leaf, chain := splitChain(rec.Certificate)

		return []exportFile{
			{name: "privkey.pem", content: toPKCS8(rec.Key), perm: privatePerm},
			{name: "cert.pem", content: leaf, perm: publicPerm},
			{name: "chain.pem", content: chain, perm: publicPerm},
			{name: "fullchain.pem", content: leaf + chain, perm: publicPerm},
		}
	}

	return []exportFile{
		{name: svc.KeyFile, content: rec.Key, perm: privatePerm},
		{name: svc.CertFile, content: rec.Certificate, perm: publicPerm},
	}
}

// splitChain splits a PEM certificate chain into the leaf certificate and the issuer chain.
// If the chain cannot be decoded, it is returned as the leaf certificate.
func splitChain(chain string) (string, string) {
	var leaf, issuers bytes.Buffer

	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		target := &issuers
		if leaf.Len() == 0 {
			target = &leaf
		}

		if err := pem.Encode(target, block); err != nil {
			break
		}
	}

	if leaf.Len() == 0 {
		return ensureTrailingNewline(chain), ""
	}

	return leaf.String(), issuers.String()
}

// toPKCS8 converts a PEM private key (PKCS#1, SEC 1 or PKCS#8) to PKCS#8 ("PRIVATE KEY"), as Let's Encrypt clients do.
// If the key cannot be decoded, it is returned unchanged.
func toPKCS8(key string) string {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return ensureTrailingNewline(key)
	}

	var (
		parsed interface{}
		err    error
	)

	switch block.Type {
	case "PRIVATE KEY":
		return ensureTrailingNewline(key)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return ensureTrailingNewline(key)
	}

	if err != nil {
		return ensureTrailingNewline(key)
	}

	der, err := x509.MarshalPKCS8PrivateKey(parsed)
	if err != nil {
		return ensureTrailingNewline(key)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}

	return s + "\n"
}
