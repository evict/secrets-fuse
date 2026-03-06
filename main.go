package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/evict/secrets-fuse/guard"
	"github.com/evict/secrets-fuse/secretmanager"
	"gopkg.in/yaml.v3"
)

type Config struct {
	OPAccount string `yaml:"op_account"`
	Secrets   []struct {
		Path          string   `yaml:"path"`             // app-visible path to intercept (guard mode)
		Reference     string   `yaml:"reference"`        // op:// reference
		Filename      string   `yaml:"filename"`         // FUSE filename
		MaxReads      int32    `yaml:"max_reads"`        // 0 = unlimited
		AllowedCmds   []string `yaml:"allowed_cmds"`     // glob patterns (legacy FUSE mode)
		TrustedHashes []string `yaml:"trusted_binaries"` // SHA-256 hashes (guard mode)
		SymlinkTo     string   `yaml:"symlink_to"`       // symlink to secret (legacy FUSE mode)
		Writable      bool     `yaml:"writable"`
		OPAccount     string   `yaml:"op_account"`
	} `yaml:"secrets"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- config path is user-specified
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return parseConfig(data)
}

func loadConfigFromOP(ctx context.Context, ref string, account string) (*Config, error) {
	manager, err := secretmanager.NewOnePasswordManager(ctx, []string{ref}, account)
	if err != nil {
		return nil, fmt.Errorf("init 1password for config: %w", err)
	}
	data, err := manager.Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve config ref %s: %w", ref, err)
	}
	return parseConfig([]byte(data))
}

func parseConfig(data []byte) (*Config, error) {
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
	if home, err := os.UserHomeDir(); err == nil {
		configPath := home + "/.config/secret-fuse.conf"
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}
	return "config.yaml"
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func main() {
	// Child mode: re-exec'd by guard, set up seccomp and exec target
	if guard.IsChild() {
		args := os.Args[1:]
		if len(args) == 0 {
			log.Fatal("child mode: no target command")
		}
		target, err := exec.LookPath(args[0])
		if err != nil {
			log.Fatalf("child: lookup %s: %v", args[0], err) // #nosec G706 -- args[0] is the command name
		}
		if err := guard.RunChild(target, args); err != nil {
			log.Fatalf("child: %v", err)
		}
		return
	}

	// Parent mode
	configPath := flag.String("config", "", "Path to configuration file")
	configRef := flag.String("config-ref", "", "1Password reference for config (e.g. op://vault/item/field)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	hashBinary := flag.String("hash", "", "Print SHA-256 hash of a binary and exit")
	flag.Parse()

	// Utility: hash a binary for config
	if *hashBinary != "" {
		printBinaryHash(*hashBinary)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: secrets-guard [flags] -- <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "       secrets-guard -hash /usr/bin/myapp\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx := context.Background()
	account := os.Getenv("OP_ACCOUNT")

	var cfg *Config
	var err error
	if *configRef != "" {
		cfg, err = loadConfigFromOP(ctx, *configRef, account)
		if err != nil {
			log.Fatalf("Failed to load config from 1Password: %v", err)
		}
		log.Printf("config loaded from 1Password: %s", *configRef)
	} else {
		cfgPath := resolveConfigPath(*configPath)
		cfg, err = loadConfig(cfgPath)
		if err != nil {
			log.Fatalf("Failed to load config from %s: %v", cfgPath, err)
		}
	}

	secrets := make([]guard.SecretMapping, 0, len(cfg.Secrets))
	for i, s := range cfg.Secrets {
		p := s.Path
		if p == "" {
			log.Fatalf("secret %d: 'path' is required (the path the app tries to open)", i)
		}
		p = expandPath(p)

		filename := s.Filename
		if filename == "" {
			filename = filepath.Base(p)
		}

		secrets = append(secrets, guard.SecretMapping{
			Path:          p,
			Reference:     s.Reference,
			Filename:      filename,
			TrustedHashes: s.TrustedHashes,
			MaxReads:      s.MaxReads,
			Writable:      s.Writable,
		})
	}

	if len(secrets) == 0 {
		log.Fatal("no secrets configured (each secret needs a 'path' field)")
	}

	refs := make([]string, len(secrets))
	for i, s := range secrets {
		refs[i] = s.Reference
	}

	if account == "" {
		account = cfg.OPAccount
	}
	manager, err := secretmanager.NewOnePasswordManager(ctx, refs, account)
	if err != nil {
		log.Fatalf("Failed to initialize 1Password: %v", err)
	}

	target, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatalf("command not found: %s", args[0])
	}

	g := guard.New(manager, secrets, *debug)

	fmt.Printf("secrets-guard: intercepting %d secret path(s)\n", len(secrets))
	for _, s := range secrets {
		trustInfo := "any binary"
		if len(s.TrustedHashes) > 0 {
			trustInfo = fmt.Sprintf("%d trusted hash(es)", len(s.TrustedHashes))
		}
		fmt.Printf("  %s → %s [%s]\n", s.Path, s.Reference, trustInfo)
	}
	fmt.Printf("secrets-guard: running %s\n", target)

	if err := g.Run(target, args); err != nil {
		log.Fatalf("guard: %v", err)
	}
}

func printBinaryHash(path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("resolve path: %v", err)
	}
	f, err := os.Open(abs) // #nosec G304 -- path is user-specified for hashing
	if err != nil {
		log.Fatalf("open %s: %v", abs, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatalf("hash %s: %v", abs, err)
	}
	fmt.Println("sha256:" + hex.EncodeToString(h.Sum(nil)))
}
