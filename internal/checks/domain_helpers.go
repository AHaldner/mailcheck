package checks

import "strings"

func isSubdomain(domain string) bool {
	return strings.Count(domain, ".") >= 2
}

func resendHelperHost(domain string) string {
	return "send." + domain
}

func parentDomains(domain string) []string {
	labels := strings.Split(domain, ".")
	if len(labels) < 3 {
		return nil
	}

	parents := make([]string, 0, len(labels)-2)
	for index := 1; index < len(labels)-1; index++ {
		parents = append(parents, strings.Join(labels[index:], "."))
	}

	return parents
}
