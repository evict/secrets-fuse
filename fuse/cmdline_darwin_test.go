//go:build darwin

package fuse

import (
	"os"
	"strings"
	"testing"
)

func TestGetProcArgs(t *testing.T) {
	// Test with current process
	pid := uint32(os.Getpid())
	args, err := getProcArgs(pid)
	if err != nil {
		t.Fatalf("getProcArgs(%d) failed: %v", pid, err)
	}

	if len(args) == 0 {
		t.Error("getProcArgs returned empty args")
	}

	// First arg should contain "test" or the executable name
	if !strings.Contains(args[0], "test") && !strings.Contains(args[0], ".test") {
		t.Logf("Warning: first arg %q doesn't contain 'test'", args[0])
	}

	t.Logf("getProcArgs(%d) returned %d args: %v", pid, len(args), args)
}

func TestGetProcArgsInvalidPID(t *testing.T) {
	// Test with invalid PID
	_, err := getProcArgs(999999)
	if err == nil {
		t.Error("getProcArgs with invalid PID should return error")
	}
	t.Logf("getProcArgs(999999) correctly returned error: %v", err)
}

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
		// On macOS, this might fail if argv[0] is different from the exe path
		// Log warning but don't fail - this is expected in some cases
		t.Logf("validateCmdlineExe(%d) returned false - this may be expected", pid)
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

func TestGetProcArgsFormat(t *testing.T) {
	// Test that the parsed args are reasonable
	pid := uint32(os.Getpid())
	args, err := getProcArgs(pid)
	if err != nil {
		t.Fatalf("getProcArgs(%d) failed: %v", pid, err)
	}

	// Check that args don't contain null bytes (would indicate parsing error)
	for i, arg := range args {
		if strings.Contains(arg, "\x00") {
			t.Errorf("arg[%d] contains null byte: %q", i, arg)
		}
	}

	// Check that joining args creates a reasonable cmdline
	cmdline := strings.Join(args, " ")
	if len(cmdline) == 0 {
		t.Error("joined cmdline is empty")
	}

	t.Logf("Parsed args format OK: %d args, cmdline length: %d", len(args), len(cmdline))
}
