package secretmanager

import "context"

type Secret struct {
	Reference string
	Value     string
}

type SecretManager interface {
	// Resolve fetches the secret value for the given reference
	Resolve(ctx context.Context, reference string) (string, error)

	// ListSecrets returns available secret references (for directory listing)
	ListSecrets(ctx context.Context) ([]string, error)

	// Name returns the provider name (e.g., "1password", "vault")
	Name() string
}
