package update

import (
	"fmt"
	"regexp"
	"strings"
)

var semanticVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

type semanticVersion struct {
	core [3]string
	pre  []string
}

// ValidVersion reports whether value is a SemVer version with a v prefix.
func ValidVersion(value string) bool {
	_, ok := parseVersion(value)
	return ok
}

// CompareVersions compares two SemVer versions with v prefixes. It returns -1
// when left has lower precedence, 0 when they have equal precedence, and 1
// when left has higher precedence. Build metadata does not affect precedence.
func CompareVersions(left, right string) (int, error) {
	leftVersion, ok := parseVersion(left)
	if !ok {
		return 0, fmt.Errorf("invalid semantic version %q", left)
	}

	rightVersion, ok := parseVersion(right)
	if !ok {
		return 0, fmt.Errorf("invalid semantic version %q", right)
	}

	for index := range leftVersion.core {
		if result := compareNumeric(leftVersion.core[index], rightVersion.core[index]); result != 0 {
			return result, nil
		}
	}

	return comparePreRelease(leftVersion.pre, rightVersion.pre), nil
}

func parseVersion(value string) (semanticVersion, bool) {
	match := semanticVersionPattern.FindStringSubmatch(value)
	if match == nil {
		return semanticVersion{}, false
	}

	version := semanticVersion{core: [3]string{match[1], match[2], match[3]}}
	if match[4] == "" {
		return version, true
	}

	version.pre = strings.Split(match[4], ".")
	for _, identifier := range version.pre {
		if isNumeric(identifier) && len(identifier) > 1 && identifier[0] == '0' {
			return semanticVersion{}, false
		}
	}

	return version, true
}

func comparePreRelease(left, right []string) int {
	if len(left) == 0 && len(right) == 0 {
		return 0
	}
	if len(left) == 0 {
		return 1
	}
	if len(right) == 0 {
		return -1
	}

	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		leftIdentifier := left[index]
		rightIdentifier := right[index]
		leftNumeric := isNumeric(leftIdentifier)
		rightNumeric := isNumeric(rightIdentifier)

		switch {
		case leftNumeric && rightNumeric:
			if result := compareNumeric(leftIdentifier, rightIdentifier); result != 0 {
				return result
			}
		case leftNumeric:
			return -1
		case rightNumeric:
			return 1
		case leftIdentifier < rightIdentifier:
			return -1
		case leftIdentifier > rightIdentifier:
			return 1
		}
	}

	return compareNumericLength(len(left), len(right))
}

func compareNumeric(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}

	if result := compareNumericLength(len(left), len(right)); result != 0 {
		return result
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareNumericLength(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func isNumeric(value string) bool {
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
