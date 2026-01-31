//go:build linux

package fuse

import (
	"os"
	"strings"
	"testing"
)

func TestGetCmdline(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	cmdline := getCmdline(pid)
	
	if cmdline == "" {
		t.Error("getCmdline returned empty string")
	}

	// Should contain at least the executable name
	if !strings.Contains(cmdline, "test") && !strings.Contains(cmdline, ".test") {
		t.Logf("Warning: cmdline %q doesn't contain 'test'", cmdline)
	}

	t.Logf("getCmdline(%d) returned: %q", pid, cmdline)
}

func TestGetCmdlineInvalidPID(t *testing.T) {
	// Test with invalid PID - should return empty string
	cmdline := getCmdline(999999)
	if cmdline != "" {
		t.Errorf("getCmdline(999999) should return empty string, got: %q", cmdline)
	}
}

func TestGetExePath(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	exePath, err := getExePath(pid)
	if err != nil {
		t.Fatalf("getExePath(%d) failed: %v", pid, err)
	}

	if exePath == "" {
		t.Error("getExePath returned empty path")
	}

	// Verify the path exists
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		t.Errorf("getExePath returned non-existent path: %q", exePath)
	}

	t.Logf("getExePath(%d) returned: %q", pid, exePath)
}

func TestGetExePathInvalidPID(t *testing.T) {
	// Test with invalid PID
	_, err := getExePath(999999)
	if err == nil {
		t.Error("getExePath with invalid PID should return error")
	}
	t.Logf("getExePath(999999) correctly returned error: %v", err)
}

func TestValidateCmdlineExe(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	valid := validateCmdlineExe(pid)
	
	if !valid {
		t.Errorf("validateCmdlineExe(%d) returned false for current process", pid)
	} else {
		t.Logf("validateCmdlineExe(%d) returned true", pid)
	}
}

func TestValidateCmdlineExeInvalidPID(t *testing.T) {
	// Test with invalid PID - should return false
	valid := validateCmdlineExe(999999)
	if valid {
		t.Error("validateCmdlineExe(999999) should return false")
	}
}

func TestGetCmdlineFormat(t *testing.T) {
	// Test that cmdline format is correct (space-separated)
	pid := uint32(os.Getpid())
	cmdline := getCmdline(pid)
	
	if cmdline == "" {
		t.Fatal("getCmdline returned empty string")
	}

	// Cmdline should not contain null bytes
	if strings.Contains(cmdline, "\x00") {
		t.Error("cmdline contains null bytes")
	}

	// Should have at least one argument (the executable)
	args := strings.Split(cmdline, " ")
	if len(args) == 0 {
		t.Error("cmdline split into zero arguments")
	}

	t.Logf("Cmdline format OK: %d space-separated args", len(args))
}

func TestValidateCmdlineExeSymlink(t *testing.T) {
	// This test verifies that the function handles symlinks correctly
	pid := uint32(os.Getpid())
	
	// Get the actual exe path
	exePath, err := getExePath(pid)
	if err != nil {
		t.Fatalf("getExePath failed: %v", err)
	}

	// The validation should pass for the current process
	valid := validateCmdlineExe(pid)
	if !valid {
		t.Errorf("validateCmdlineExe failed for current process with exe: %q", exePath)
	}
}
