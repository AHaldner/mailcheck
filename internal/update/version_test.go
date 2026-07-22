package update

import "testing"

func TestValidVersion(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "release", value: "v1.2.3", want: true},
		{name: "zero release", value: "v0.0.0", want: true},
		{name: "pre-release", value: "v1.2.3-alpha", want: true},
		{name: "numeric pre-release", value: "v1.2.3-alpha.1", want: true},
		{name: "pre-release with hyphen", value: "v1.2.3-rc-1", want: true},
		{name: "build metadata", value: "v1.2.3+build.5", want: true},
		{name: "pre-release and build metadata", value: "v1.2.3-rc.1+build.5", want: true},
		{name: "development value", value: "dev", want: false},
		{name: "missing prefix", value: "1.2.3", want: false},
		{name: "missing patch", value: "v1.2", want: false},
		{name: "extra core component", value: "v1.2.3.4", want: false},
		{name: "major leading zero", value: "v01.2.3", want: false},
		{name: "minor leading zero", value: "v1.02.3", want: false},
		{name: "patch leading zero", value: "v1.2.03", want: false},
		{name: "numeric pre-release leading zero", value: "v1.2.3-01", want: false},
		{name: "numeric pre-release component leading zero", value: "v1.2.3-alpha.01", want: false},
		{name: "empty pre-release", value: "v1.2.3-", want: false},
		{name: "empty build", value: "v1.2.3+", want: false},
		{name: "empty pre-release component", value: "v1.2.3-alpha..1", want: false},
		{name: "empty build component", value: "v1.2.3+build..1", want: false},
		{name: "invalid pre-release character", value: "v1.2.3-alpha_1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidVersion(tt.value); got != tt.want {
				t.Fatalf("ValidVersion(%q) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func TestStableVersion(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "release", value: "v1.3.0", want: true},
		{name: "release with build metadata", value: "v1.3.0+packaged", want: true},
		{name: "pre-release", value: "v1.3.0-rc.1", want: false},
		{name: "Git describe", value: "v1.3.0-12-gabcdef-dirty", want: false},
		{name: "pre-release with build metadata", value: "v1.3.0-rc.1+packaged", want: false},
		{name: "invalid", value: "dev", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StableVersion(tt.value); got != tt.want {
				t.Fatalf("StableVersion(%q) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name        string
		left, right string
		want        int
	}{
		{name: "patch", left: "v1.2.3", right: "v1.2.4", want: -1},
		{name: "minor numeric", left: "v1.10.0", right: "v1.9.0", want: 1},
		{name: "major", left: "v2.0.0", right: "v1.99.99", want: 1},
		{name: "arbitrarily long core identifiers", left: "v100000000000000000000.0.0", right: "v99999999999999999999.0.0", want: 1},
		{name: "numeric pre-release below non-numeric", left: "v2.0.0-alpha.1", right: "v2.0.0-alpha.beta", want: -1},
		{name: "pre-release below release", left: "v2.0.0-rc.1", right: "v2.0.0", want: -1},
		{name: "additional pre-release identifier", left: "v1.0.0-alpha", right: "v1.0.0-alpha.1", want: -1},
		{name: "pre-release numeric ordering", left: "v1.0.0-beta.2", right: "v1.0.0-beta.11", want: -1},
		{name: "pre-release lexical ordering", left: "v1.0.0-beta", right: "v1.0.0-rc", want: -1},
		{name: "arbitrarily long numeric pre-release identifiers", left: "v1.0.0-100000000000000000000", right: "v1.0.0-99999999999999999999", want: 1},
		{name: "build metadata ignored", left: "v1.2.3+one", right: "v1.2.3+two", want: 0},
		{name: "build metadata ignored on pre-release", left: "v1.2.3-rc.1+one", right: "v1.2.3-rc.1+two", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareVersions(tt.left, tt.right)
			if err != nil || got != tt.want {
				t.Fatalf("CompareVersions(%q, %q) = %d, %v, want %d, nil", tt.left, tt.right, got, err, tt.want)
			}
		})
	}
}

func TestCompareVersionsRejectsInvalidVersion(t *testing.T) {
	tests := []struct {
		name        string
		left, right string
	}{
		{name: "invalid left", left: "dev", right: "v1.2.3"},
		{name: "invalid right", left: "v1.2.3", right: "1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CompareVersions(tt.left, tt.right); err == nil {
				t.Fatalf("CompareVersions(%q, %q) error = nil, want invalid version error", tt.left, tt.right)
			}
		})
	}
}
