package cli

import (
	"io"
	"testing"
)

func TestBuildSelectorsDeduplicatesExplicitSelectors(t *testing.T) {
	got := BuildSelectors([]string{"Google", "custom", "google", "custom"})
	want := []string{"google", "custom"}

	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestValidateDomainRejectsEmpty(t *testing.T) {
	if err := ValidateDomain(""); err == nil {
		t.Fatal("ValidateDomain() error = nil, want error")
	}
}

func TestParseArgsAllowsDomainBeforeFlags(t *testing.T) {
	got, err := ParseArgs([]string{"example.com", "--json", "--timeout", "5s"}, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs() error = %v", err)
	}

	if got.Domain != "example.com" {
		t.Fatalf("Domain = %q, want %q", got.Domain, "example.com")
	}

	if !got.JSON {
		t.Fatal("JSON = false, want true")
	}

	if got.Timeout.Seconds() != 5 {
		t.Fatalf("Timeout = %v, want 5s", got.Timeout)
	}
}
