package version

import "testing"

func TestCurrentPrefersInjectedVersion(t *testing.T) {
	oldValue := Value
	Value = "v1.2.3"
	defer func() { Value = oldValue }()

	if got := Current(); got != "v1.2.3" {
		t.Fatalf("Current() = %q, want %q", got, "v1.2.3")
	}
}

func TestCurrentPrefersGitDescribeForDevBuilds(t *testing.T) {
	oldValue := Value
	oldGitDescribe := GitDescribe
	Value = "dev"
	GitDescribe = func() string { return "v1.0.0-3-ge73f3da-dirty" }
	defer func() {
		Value = oldValue
		GitDescribe = oldGitDescribe
	}()

	if got := Current(); got != "v1.0.0-3-ge73f3da-dirty" {
		t.Fatalf("Current() = %q, want %q", got, "v1.0.0-3-ge73f3da-dirty")
	}
}
