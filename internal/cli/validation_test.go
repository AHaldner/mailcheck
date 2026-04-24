package cli

import "testing"

func TestValidateDomainRejectsEmpty(t *testing.T) {
	if err := ValidateDomain(""); err == nil {
		t.Fatal("ValidateDomain() error = nil, want error")
	}
}
