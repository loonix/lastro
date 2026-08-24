package main

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveShaTemplate(t *testing.T) {
	head := func() (string, error) { return "AB12cd34ef567890ab12cd34ef567890ab12cd34\n", nil }

	got, err := resolveShaTemplate("bolina/{sha}/check/tests", head)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := "bolina/ab12cd34ef567890ab12cd34ef567890ab12cd34/check/tests"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// No placeholder: git is never consulted.
	neverCalled := func() (string, error) { t.Fatal("headFn called without {sha}"); return "", nil }
	if got, err := resolveShaTemplate("bolina/static/check", neverCalled); err != nil || got != "bolina/static/check" {
		t.Fatalf("passthrough failed: %q, %v", got, err)
	}

	// Git unavailable with a placeholder is a hard error, not a fallback.
	broken := func() (string, error) { return "", errors.New("not a repo") }
	if _, err := resolveShaTemplate("x/{sha}", broken); err == nil {
		t.Fatal("accepted {sha} with no git HEAD")
	}

	// A non-hex HEAD (e.g. an error message on stdout) is refused.
	garbage := func() (string, error) { return "fatal: not a git repository", nil }
	if _, err := resolveShaTemplate("x/{sha}", garbage); err == nil {
		t.Fatal("accepted non-hex HEAD")
	}
}

func TestValidateResource(t *testing.T) {
	ok := [][2]string{
		{"git", "bolina/ab12cd/check/zig-build-test"},
		{"ci", "a"},
		{"a-b", "x.y_z/w-1"},
	}
	for _, c := range ok {
		if err := validateResource(c[0], c[1]); err != nil {
			t.Errorf("validateResource(%q, %q) = %v, want nil", c[0], c[1], err)
		}
	}
	bad := [][2]string{
		{"Git", "x"},              // uppercase namespace
		{"git", "X"},              // uppercase path
		{"git", "a//b"},           // empty segment
		{"git", "a/../b"},         // dotdot segment
		{"git", "."},              // dot segment
		{"", "x"},                 // empty namespace
		{"git", ""},               // empty path
		{"git", strings.Repeat("a", 181)}, // path too long
		{strings.Repeat("n", 33), "x"},    // namespace too long
		{"git", "a/{sha}/b"},      // unresolved placeholder chars
	}
	for _, c := range bad {
		if err := validateResource(c[0], c[1]); err == nil {
			t.Errorf("validateResource(%q, %q) accepted, want error", c[0], c[1])
		}
	}
}
