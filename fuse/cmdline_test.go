package fuse

import (
	"os"
	"strings"
	"testing"
)

func TestGetCmdline(t *testing.T) {
	pid := uint32(os.Getpid())

	cmdline := getCmdline(pid)
	if cmdline == "" {
		t.Fatal("getCmdline returned empty string")
	}

	if !strings.Contains(cmdline, "test") {
		t.Errorf("cmdline should contain 'test', got: %s", cmdline)
	}

	t.Logf("cmdline for PID %d: %s", pid, cmdline)
}

func TestGetExePath(t *testing.T) {
	pid := uint32(os.Getpid())

	exePath, err := getExePath(pid)
	if err != nil {
		t.Fatalf("getExePath failed: %v", err)
	}

	if exePath == "" {
		t.Fatal("getExePath returned empty string")
	}

	t.Logf("exePath for PID %d: %s", pid, exePath)
}

func TestValidateCmdlineExe(t *testing.T) {
	pid := uint32(os.Getpid())

	if !validateCmdlineExe(pid) {
		t.Error("validateCmdlineExe failed for current process")
	}
}

func TestCmdlineConstruction(t *testing.T) {
	pid := uint32(os.Getpid())

	cmdline := getCmdline(pid)
	if cmdline == "" {
		t.Fatal("getCmdline returned empty string")
	}

	args := strings.Fields(cmdline)
	if len(args) == 0 {
		t.Fatal("no arguments in cmdline")
	}

	if args[0] == "" {
		t.Error("first arg is empty")
	}

	t.Logf("Successfully constructed cmdline: %s", cmdline)
}
