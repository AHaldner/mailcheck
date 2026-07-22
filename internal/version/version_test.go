package version

import (
	"runtime/debug"
	"testing"
)

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

func TestReleaseVersionIgnoresExactTagGitDescribeForDevelopmentBuild(t *testing.T) {
	oldValue := Value
	oldGitDescribe := GitDescribe
	oldReadBuildInfo := ReadBuildInfo
	Value = "dev"
	GitDescribe = func() string { return "v1.2.3" }
	ReadBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true
	}
	t.Cleanup(func() {
		Value = oldValue
		GitDescribe = oldGitDescribe
		ReadBuildInfo = oldReadBuildInfo
	})

	if got := ReleaseVersion(); got != "dev" {
		t.Fatalf("ReleaseVersion() = %q, want development version", got)
	}
}

func TestReleaseVersionUsesModuleVersionWithoutGitDescribeOverride(t *testing.T) {
	oldValue := Value
	oldGitDescribe := GitDescribe
	oldReadBuildInfo := ReadBuildInfo
	Value = "dev"
	GitDescribe = func() string { return "v9.9.9" }
	ReadBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true
	}
	t.Cleanup(func() {
		Value = oldValue
		GitDescribe = oldGitDescribe
		ReadBuildInfo = oldReadBuildInfo
	})

	if got := ReleaseVersion(); got != "v1.2.3" {
		t.Fatalf("ReleaseVersion() = %q, want %q", got, "v1.2.3")
	}
}
