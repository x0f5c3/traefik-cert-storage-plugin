package certstorage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackExportFilesRemovesUninstalledBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	backup := filepath.Join(dir, ".cert.pem.backup-test")

	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, backup); err != nil {
		t.Fatal(err)
	}

	replacements := []exportReplacement{{
		path:    path,
		backup:  backup,
		hadFile: true,
	}}
	if err := rollbackExportFiles(replacements); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup still exists or could not be checked: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("live file = %q, want %q", content, "original")
	}
}
