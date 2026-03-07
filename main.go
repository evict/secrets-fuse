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

	"github.com/evict/secrets-guard/guard"
	"github.com/evict/secrets-guard/secretmanager"
)

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
	secretPath := flag.String("path", "", "File path to intercept (the path the app tries to open)")
	reference := flag.String("ref", "", "1Password reference (e.g. op://vault/item/field)")
	account := flag.String("account", os.Getenv("OP_ACCOUNT"), "1Password account (default: $OP_ACCOUNT)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	hashBinary := flag.String("hash", "", "Print SHA-256 hash of a binary and exit")
	flag.Parse()

	// Utility: hash a binary
	if *hashBinary != "" {
		printBinaryHash(*hashBinary)
		return
	}

	args := flag.Args()
	if *secretPath == "" || *reference == "" || len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: secrets-guard -path <file> -ref <op://...> [flags] -- <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "       secrets-guard -hash /usr/bin/myapp\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx := context.Background()

	p := expandPath(*secretPath)
	secrets := []guard.SecretMapping{{
		Path:      p,
		Reference: *reference,
		Filename:  filepath.Base(p),
	}}

	manager, err := secretmanager.NewOnePasswordManager(ctx, []string{*reference}, *account)
	if err != nil {
		log.Fatalf("Failed to initialize 1Password: %v", err)
	}

	target, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatalf("command not found: %s", args[0])
	}

	g := guard.New(manager, secrets, *debug)

	fmt.Printf("secrets-guard: intercepting %s -> %s\n", p, *reference)
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
