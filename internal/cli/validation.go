package cli

import (
	"errors"
	"fmt"
	"strings"
)

func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return errors.New("domain must not be empty")
	}

	if len(domain) > 253 {
		return errors.New("domain exceeds maximum length")
	}

	if strings.Contains(domain, "://") || strings.Contains(domain, "/") || strings.Contains(domain, " ") {
		return errors.New("domain must be a bare hostname")
	}

	if before, ok := strings.CutSuffix(domain, "."); ok {
		domain = before
	}

	if !strings.Contains(domain, ".") {
		return errors.New("domain must contain at least one dot")
	}

	labels := strings.SplitSeq(domain, ".")
	for label := range labels {
		if label == "" {
			return errors.New("domain contains an empty label")
		}

		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds maximum length", label)
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain label %q must not start or end with '-'", label)
		}

		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}

			return fmt.Errorf("domain label %q contains invalid character %q", label, r)
		}
	}

	return nil
}
