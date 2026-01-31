//go:build darwin

package fuse

import (
	"os"
	"strings"
	"testing"
)

func TestGetCmdlineDarwin(t *testing.T) {
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

func TestGetExePathDarwin(t *testing.T) {
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

func TestGetProcArgsDarwin(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	
	args, err := getProcArgs(pid)
	if err != nil {
		t.Fatalf("getProcArgs failed: %v", err)
	}
	
	if len(args) == 0 {
		t.Fatal("getProcArgs returned empty args")
	}
	
	// First arg should be the executable or test name
	if args[0] == "" {
		t.Error("first arg is empty")
	}
	
	t.Logf("args for PID %d: %v", pid, args)
}

func TestValidateCmdlineExeDarwin(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	
	if !validateCmdlineExe(pid) {
		t.Error("validateCmdlineExe failed for current process")
	}
}

func TestCmdlineConstructionDarwin(t *testing.T) {
	// This test validates that we can construct the full command line
	// from the arguments returned by getProcArgs
	pid := uint32(os.Getpid())
	
	args, err := getProcArgs(pid)
	if err != nil {
		t.Fatalf("getProcArgs failed: %v", err)
	}
	
	if len(args) == 0 {
		t.Fatal("no arguments returned")
	}
	
	// Construct cmdline from args
	cmdline := strings.Join(args, " ")
	
	// Verify it matches getCmdline
	expectedCmdline := getCmdline(pid)
	if cmdline != expectedCmdline {
		t.Errorf("constructed cmdline doesn't match getCmdline:\nconstructed: %s\nexpected: %s", 
			cmdline, expectedCmdline)
	}
	
	t.Logf("Successfully constructed cmdline: %s", cmdline)
}
