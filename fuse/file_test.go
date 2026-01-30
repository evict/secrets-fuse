package fuse

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// MockSecretManager implements SecretManager for testing
type MockSecretManager struct {
	secrets map[string]string
}

func NewMockSecretManager() *MockSecretManager {
	return &MockSecretManager{
		secrets: make(map[string]string),
	}
}

func (m *MockSecretManager) Resolve(ctx context.Context, reference string) (string, error) {
	if val, ok := m.secrets[reference]; ok {
		return val, nil
	}
	return "", nil
}

func (m *MockSecretManager) Write(ctx context.Context, reference string, value string) error {
	m.secrets[reference] = value
	return nil
}

func (m *MockSecretManager) ListSecrets(ctx context.Context) ([]string, error) {
	keys := make([]string, 0, len(m.secrets))
	for k := range m.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *MockSecretManager) Name() string {
	return "mock"
}

func TestWriteThenRead(t *testing.T) {
	// Create temp mount point
	mountPoint, err := os.MkdirTemp("", "secrets-fuse-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	// Setup mock manager with initial content
	manager := NewMockSecretManager()
	ref := "op://test/item/field"
	initialContent := "initial-secret-value"
	manager.secrets[ref] = initialContent

	// Create root with one secret
	secrets := []SecretConfig{
		{
			Reference: ref,
			Filename:  "secret.txt",
			Writable:  true,
		},
	}
	root := NewSecretRoot(manager, secrets, 0)

	// Mount
	zero := time.Duration(0)
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug: testing.Verbose(),
		},
		AttrTimeout:     &zero,
		EntryTimeout:    &zero,
		NegativeTimeout: &zero,
	}

	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer server.Unmount()

	secretPath := filepath.Join(mountPoint, "secret.txt")

	// Read initial content
	content, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("initial read failed: %v", err)
	}
	if string(content) != initialContent {
		t.Errorf("initial read: got %q, want %q", content, initialContent)
	}

	// Write new content
	newContent := "updated-secret-value"
	err = os.WriteFile(secretPath, []byte(newContent), 0600)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Verify manager received the write
	if manager.secrets[ref] != newContent {
		t.Errorf("manager not updated: got %q, want %q", manager.secrets[ref], newContent)
	}

	// Read back - this is the critical test
	content, err = os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read after write failed: %v", err)
	}
	if string(content) != newContent {
		t.Errorf("read after write: got %q, want %q", content, newContent)
	}
}

func TestWriteViaRename(t *testing.T) {
	// Create temp mount point
	mountPoint, err := os.MkdirTemp("", "secrets-fuse-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	// Setup mock manager with initial content
	manager := NewMockSecretManager()
	ref := "op://test/item/field"
	initialContent := "initial-secret-value"
	manager.secrets[ref] = initialContent

	// Create root with one secret
	secrets := []SecretConfig{
		{
			Reference: ref,
			Filename:  "secret.txt",
			Writable:  true,
		},
	}
	root := NewSecretRoot(manager, secrets, 0)

	// Mount
	zero := time.Duration(0)
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Debug: testing.Verbose(),
		},
		AttrTimeout:     &zero,
		EntryTimeout:    &zero,
		NegativeTimeout: &zero,
	}

	server, err := fs.Mount(mountPoint, root, opts)
	if err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer server.Unmount()

	secretPath := filepath.Join(mountPoint, "secret.txt")

	// Read initial content
	content, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("initial read failed: %v", err)
	}
	if string(content) != initialContent {
		t.Errorf("initial read: got %q, want %q", content, initialContent)
	}

	// Simulate what Amp does: mkdir, write to temp file, rename
	tempDir := filepath.Join(mountPoint, ".amp-temp")
	err = os.Mkdir(tempDir, 0755)
	if err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	tempFile := filepath.Join(tempDir, "secret.txt")
	newContent := "updated-via-rename"
	err = os.WriteFile(tempFile, []byte(newContent), 0600)
	if err != nil {
		t.Fatalf("write temp file failed: %v", err)
	}

	// Rename temp file to secret
	err = os.Rename(tempFile, secretPath)
	if err != nil {
		t.Fatalf("rename failed: %v", err)
	}

	// Verify manager received the write
	if manager.secrets[ref] != newContent {
		t.Errorf("manager not updated: got %q, want %q", manager.secrets[ref], newContent)
	}

	// Read back - this is the critical test
	content, err = os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read after rename failed: %v", err)
	}
	if string(content) != newContent {
		t.Errorf("read after rename: got %q, want %q", content, newContent)
	}
}
