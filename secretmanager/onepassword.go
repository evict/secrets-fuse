package secretmanager

import (
	"context"
	"fmt"
	"strings"

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

// parseReference extracts vault, item, and field from "op://vault/item/field"
func parseReference(reference string) (vaultID, itemID, fieldID string, err error) {
	if !strings.HasPrefix(reference, "op://") {
		return "", "", "", fmt.Errorf("invalid reference format: must start with op://")
	}
	parts := strings.Split(strings.TrimPrefix(reference, "op://"), "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid reference format: expected op://vault/item/field")
	}
	return parts[0], parts[1], parts[2], nil
}

func (m *OnePasswordManager) Write(ctx context.Context, reference string, value string) error {
	vaultID, itemID, fieldID, err := parseReference(reference)
	if err != nil {
		return err
	}

	item, err := m.client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return fmt.Errorf("failed to get item: %w", err)
	}

	// Handle Document items (file-based)
	if item.Category == onepassword.ItemCategoryDocument && item.Document != nil {
		return m.writeDocument(ctx, item, fieldID, []byte(value))
	}

	// Handle file attachments
	for _, file := range item.Files {
		if file.Attributes.Name == fieldID {
			return m.writeFileAttachment(ctx, item, file, []byte(value))
		}
	}

	// Handle field-based items
	return m.writeField(ctx, item, fieldID, value)
}

func (m *OnePasswordManager) writeDocument(ctx context.Context, item onepassword.Item, filename string, content []byte) error {
	// Read current content for backup
	oldContent, err := m.client.Items().Files().Read(ctx, item.VaultID, item.ID, *item.Document)
	if err != nil {
		return fmt.Errorf("failed to read current document: %w", err)
	}

	// Check if backup already exists and delete it
	backupFieldID := "backup_" + item.Document.Name
	for _, file := range item.Files {
		if file.FieldID == backupFieldID {
			item, err = m.client.Items().Files().Delete(ctx, item, file.SectionID, file.FieldID)
			if err != nil {
				return fmt.Errorf("failed to delete old backup: %w", err)
			}
			break
		}
	}

	// Attach backup as .bak file
	backupName := item.Document.Name + ".bak"
	item, err = m.client.Items().Files().Attach(ctx, item, onepassword.FileCreateParams{
		Name:    backupName,
		Content: oldContent,
		FieldID: backupFieldID,
	})
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Replace the document
	_, err = m.client.Items().Files().ReplaceDocument(ctx, item, onepassword.DocumentCreateParams{
		Name:    filename,
		Content: content,
	})
	if err != nil {
		return fmt.Errorf("failed to replace document: %w", err)
	}

	return nil
}

func (m *OnePasswordManager) writeFileAttachment(ctx context.Context, item onepassword.Item, file onepassword.ItemFile, content []byte) error {
	// Read current content for backup
	oldContent, err := m.client.Items().Files().Read(ctx, item.VaultID, item.ID, file.Attributes)
	if err != nil {
		return fmt.Errorf("failed to read current file: %w", err)
	}

	// Delete the old file
	item, err = m.client.Items().Files().Delete(ctx, item, file.SectionID, file.FieldID)
	if err != nil {
		return fmt.Errorf("failed to delete old file: %w", err)
	}

	// Attach backup
	backupName := file.Attributes.Name + ".bak"
	item, err = m.client.Items().Files().Attach(ctx, item, onepassword.FileCreateParams{
		Name:      backupName,
		Content:   oldContent,
		SectionID: file.SectionID,
		FieldID:   "backup_" + file.FieldID,
	})
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Attach new file
	_, err = m.client.Items().Files().Attach(ctx, item, onepassword.FileCreateParams{
		Name:      file.Attributes.Name,
		Content:   content,
		SectionID: file.SectionID,
		FieldID:   file.FieldID,
	})
	if err != nil {
		return fmt.Errorf("failed to attach new file: %w", err)
	}

	return nil
}

func (m *OnePasswordManager) writeField(ctx context.Context, item onepassword.Item, fieldID string, value string) error {
	var fieldIdx = -1
	var prevFieldIdx = -1
	prevFieldID := fieldID + "_previous"

	for i := range item.Fields {
		if item.Fields[i].ID == fieldID || item.Fields[i].Title == fieldID {
			fieldIdx = i
		}
		if item.Fields[i].ID == prevFieldID || item.Fields[i].Title == prevFieldID {
			prevFieldIdx = i
		}
	}

	if fieldIdx == -1 {
		return fmt.Errorf("field %q not found in item", fieldID)
	}

	oldValue := item.Fields[fieldIdx].Value

	if prevFieldIdx != -1 {
		item.Fields[prevFieldIdx].Value = oldValue
	} else {
		item.Fields = append(item.Fields, onepassword.ItemField{
			ID:        prevFieldID,
			Title:     prevFieldID,
			Value:     oldValue,
			FieldType: item.Fields[fieldIdx].FieldType,
			SectionID: item.Fields[fieldIdx].SectionID,
		})
	}

	item.Fields[fieldIdx].Value = value

	_, err := m.client.Items().Put(ctx, item)
	if err != nil {
		return fmt.Errorf("failed to update item: %w", err)
	}

	return nil
}

func (m *OnePasswordManager) ListSecrets(ctx context.Context) ([]string, error) {
	return m.secrets, nil
}

func (m *OnePasswordManager) Name() string {
	return "1password"
}
