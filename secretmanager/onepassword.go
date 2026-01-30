package secretmanager

import (
	"context"

	"github.com/1password/onepassword-sdk-go"
)

type OnePasswordManager struct {
	client  *onepassword.Client
	secrets []string // configured secret references
}

func NewOnePasswordManager(ctx context.Context, secrets []string, account string) (*OnePasswordManager, error) {
	opts := []onepassword.ClientOption{
		onepassword.WithIntegrationInfo("secrets-fuse", "1.0.0"),
	}

	if account != "" {
		opts = append(opts, onepassword.WithDesktopAppIntegration(account))
	} else {
		token := ""
		opts = append(opts, onepassword.WithServiceAccountToken(token))
	}

	client, err := onepassword.NewClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &OnePasswordManager{
		client:  client,
		secrets: secrets,
	}, nil
}

func (m *OnePasswordManager) Resolve(ctx context.Context, reference string) (string, error) {
	return m.client.Secrets().Resolve(ctx, reference)
}

func (m *OnePasswordManager) ListSecrets(ctx context.Context) ([]string, error) {
	return m.secrets, nil
}

func (m *OnePasswordManager) Name() string {
	return "1password"
}
