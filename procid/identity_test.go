package procid

import "testing"

func TestMatchesRequiresExactNameAndCmdline(t *testing.T) {
	expected := Identity{
		Name:    "bun",
		Cmdline: []string{"bun", "run", "dev"},
	}

	if !expected.Matches(Identity{Name: "bun", Cmdline: []string{"bun", "run", "dev"}}) {
		t.Fatal("expected identical identity to match")
	}

	if expected.Matches(Identity{Name: "bun", Cmdline: []string{"bun", "run", "test"}}) {
		t.Fatal("expected mismatched cmdline to be denied")
	}

	if expected.Matches(Identity{Name: "sh", Cmdline: []string{"bun", "run", "dev"}}) {
		t.Fatal("expected mismatched process name to be denied")
	}
}

func TestGuardPinsFirstIdentity(t *testing.T) {
	guard := NewGuard()
	current := Identity{Name: "bun", Cmdline: []string{"/home/me/.amp/bin/bun", "run", "dev"}}

	matched, expected, pinned := guard.PinOrMatch(current)
	if !matched {
		t.Fatal("first trusted process should be accepted")
	}
	if !pinned {
		t.Fatal("first trusted process should pin the guard identity")
	}
	if !expected.Matches(current) {
		t.Fatal("pinned identity should equal the first trusted process")
	}
}

func TestGuardRejectsDifferentFollowupIdentity(t *testing.T) {
	guard := NewGuard()
	first := Identity{Name: "bun", Cmdline: []string{"/home/me/.amp/bin/bun", "run", "dev"}}
	second := Identity{Name: "sh", Cmdline: []string{"sh", "-lc", "cat secret"}}

	if matched, _, _ := guard.PinOrMatch(first); !matched {
		t.Fatal("first identity should pin")
	}

	matched, expected, pinned := guard.PinOrMatch(second)
	if matched {
		t.Fatal("different child identity should be rejected")
	}
	if pinned {
		t.Fatal("guard identity should not repin after the first process")
	}
	if !expected.Matches(first) {
		t.Fatal("expected identity should remain the originally pinned process")
	}
}
