package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	secretfuse "github.com/evict/secrets-fuse/fuse"
	"github.com/evict/secrets-fuse/secretmanager"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Secrets []struct {
		Reference   string   `yaml:"reference"`
		Filename    string   `yaml:"filename"`
		MaxReads    int32    `yaml:"max_reads"`
		AllowedCmds []string `yaml:"allowed_cmds"`
		SymlinkTo   string   `yaml:"symlink_to"`
		Writable    bool     `yaml:"writable"`
	} `yaml:"secrets"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	// Check ~/.config/secret-fuse.conf
	if home, err := os.UserHomeDir(); err == nil {
		configPath := home + "/.config/secret-fuse.conf"
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}
	// Fallback to config.yaml in current directory
	return "config.yaml"
}

func main() {
	mountPoint := flag.String("mount", "/tmp/secrets-mount", "Mount point for secrets filesystem")
	configPath := flag.String("config", "", "Path to secrets configuration file")
	maxReads := flag.Int("max-reads", 0, "Maximum number of reads per secret (0 = unlimited)")
	debug := flag.Bool("debug", false, "Enable FUSE debug logging")
	flag.Parse()

	cfgPath := resolveConfigPath(*configPath)
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", cfgPath, err)
	}

	secrets := make([]secretfuse.SecretConfig, len(cfg.Secrets))
	for i, s := range cfg.Secrets {
		maxR := s.MaxReads
		if maxR == 0 {
			maxR = int32(*maxReads)
		}
		secrets[i] = secretfuse.SecretConfig{
			Reference:   s.Reference,
			Filename:    s.Filename,
			MaxReads:    maxR,
			AllowedCmds: s.AllowedCmds,
			SymlinkTo:   s.SymlinkTo,
			Writable:    s.Writable,
		}
	}

	ctx := context.Background()

	refs := make([]string, len(secrets))
	for i, s := range secrets {
		refs[i] = s.Reference
	}

	// Initialize secret manager (uses desktop app auth via OP_ACCOUNT or --account flag)
	account := os.Getenv("OP_ACCOUNT")
	manager, err := secretmanager.NewOnePasswordManager(ctx, refs, account)
	if err != nil {
		log.Fatalf("Failed to initialize 1Password: %v", err)
	}

	if err := os.MkdirAll(*mountPoint, 0755); err != nil {
		log.Fatalf("Failed to create mount point: %v", err)
	}

	root := secretfuse.NewSecretRoot(manager, secrets, int32(*maxReads))

	zero := time.Duration(0)
	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Name:        "secrets-fuse",
			DirectMount: true,
			Debug:       *debug,
		},
		// Disable caching to ensure fresh reads after writes
		AttrTimeout:     &zero,
		EntryTimeout:    &zero,
		NegativeTimeout: &zero,
	}

	server, err := fs.Mount(*mountPoint, root, opts)
	if err != nil {
		log.Fatalf("Mount failed: %v", err)
	}

	fmt.Printf("Secrets mounted at %s (provider: %s)\n", *mountPoint, manager.Name())
	fmt.Printf("Configured secrets:\n")
	for _, s := range secrets {
		readLimit := "unlimited"
		if s.MaxReads > 0 {
			readLimit = fmt.Sprintf("%d", s.MaxReads)
		}
		fmt.Printf("  - %s (max reads: %s)\n", s.Filename, readLimit)
	}

	var symlinks []string
	for i := range secrets {
		link, err := secrets[i].CreateSymlink(*mountPoint)
		if err != nil {
			log.Fatalf("Failed to create symlink: %v", err)
		}
		if link != "" {
			symlinks = append(symlinks, link)
			fmt.Printf("  symlink: %s\n", link)
		}
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nUnmounting...")

		for _, link := range symlinks {
			if err := os.Remove(link); err != nil {
				fmt.Printf("Failed to remove symlink %s: %v\n", link, err)
			}
		}

		// Try graceful unmount with timeout
		done := make(chan error, 1)
		go func() {
			done <- server.Unmount()
		}()

		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("Unmount failed: %v\n", err)
			}
		case <-time.After(3 * time.Second):
			fmt.Println("Unmount timed out: filesystem is busy.")
			fmt.Println("Please close any files or terminals using the mount and try again.")
			fmt.Printf("Mount point: %s\n", *mountPoint)
		}
	}()

	server.Wait()
}
