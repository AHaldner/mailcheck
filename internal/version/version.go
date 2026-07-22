package version

import (
	"os/exec"
	"runtime/debug"
	"strings"
)

var Value = "dev"

var ReadBuildInfo = debug.ReadBuildInfo

var GitDescribe = func() string {
	output, err := exec.Command("git", "describe", "--tags", "--dirty", "--always").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

func Current() string {
	if Value != "" && Value != "dev" {
		return Value
	}

	if described := GitDescribe(); described != "" {
		return described
	}

	info, ok := ReadBuildInfo()
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return Value
}

// ReleaseVersion returns only version information embedded in the binary.
// Unlike Current, it never consults the ambient Git repository.
func ReleaseVersion() string {
	if Value != "" && Value != "dev" {
		return Value
	}

	info, ok := ReadBuildInfo()
	if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return Value
}
