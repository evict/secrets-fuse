//go:build linux

package fuse

import (
	"os"
	"strings"
	"testing"
)

func TestGetCmdlineLinux(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	
	cmdline := getCmdline(pid)
	if cmdline == "" {
		t.Fatal("getCmdline returned empty string")
	}
	
	// Should contain test binary name
	if !strings.Contains(cmdline, "test") {
		t.Errorf("cmdline should contain 'test', got: %s", cmdline)
	}
	
	t.Logf("cmdline for PID %d: %s", pid, cmdline)
}

func TestGetExePathLinux(t *testing.T) {
	// Test with current process
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

func TestValidateCmdlineExeLinux(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	
	if !validateCmdlineExe(pid) {
		t.Error("validateCmdlineExe failed for current process")
	}
}

func TestCmdlineConstructionLinux(t *testing.T) {
	// This test validates that we can construct the full command line
	// from /proc/PID/cmdline
	pid := uint32(os.Getpid())
	
	cmdline := getCmdline(pid)
	if cmdline == "" {
		t.Fatal("getCmdline returned empty string")
	}
	
	// Verify cmdline contains expected components
	args := strings.Fields(cmdline)
	if len(args) == 0 {
		t.Fatal("no arguments in cmdline")
	}
	
	// First arg should be the executable
	if args[0] == "" {
		t.Error("first arg is empty")
	}
	
	t.Logf("Successfully constructed cmdline: %s", cmdline)
}

func TestProcCmdlineFormatLinux(t *testing.T) {
	// Test that we correctly read and parse /proc/PID/cmdline
	pid := uint32(os.Getpid())
	
	cmdline := getCmdline(pid)
	if cmdline == "" {
		t.Fatal("failed to get cmdline")
	}
	
	// The cmdline should be space-separated
	if !strings.Contains(cmdline, " ") {
		t.Logf("Warning: cmdline has no spaces: %s", cmdline)
	}
	
	// Verify it's not empty or just null bytes
	trimmed := strings.TrimSpace(cmdline)
	if len(trimmed) == 0 {
		t.Error("cmdline is empty after trimming")
	}
	
	t.Logf("cmdline format validated: %s", cmdline)
}
