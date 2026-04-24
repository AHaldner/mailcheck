package model

type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
	StatusInfo Status = "INFO"
)

type CheckResult struct {
	Name       string   `json:"name"`
	Status     Status   `json:"status"`
	Summary    string   `json:"summary"`
	Details    []string `json:"details,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
}

type RunResult struct {
	Domain             string        `json:"domain"`
	Rating             string        `json:"rating"`
	RatingReason       string        `json:"ratingReason,omitempty"`
	Checks             []CheckResult `json:"checks"`
	DKIMSelectorsTried []string      `json:"dkimSelectorsTried,omitempty"`
	DKIMSelectorsFound []string      `json:"dkimSelectorsFound,omitempty"`
}

func RatingFromChecks(checks []CheckResult) string {
	rating, _ := RatingFromChecksWithReason(checks)
	return rating
}

func RatingFromChecksWithReason(checks []CheckResult) (string, string) {
	var coreWarns int
	var coreFails int
	dkim := StatusWarn
	firstCoreWarn := ""
	firstCoreFail := ""

	for _, check := range checks {
		switch check.Name {
		case "MX", "SPF", "DMARC":
			switch check.Status {
			case StatusWarn:
				coreWarns++
				if firstCoreWarn == "" {
					firstCoreWarn = check.Name
				}
			case StatusFail:
				coreFails++
				if firstCoreFail == "" {
					firstCoreFail = check.Name
				}
			}
		case "DKIM":
			dkim = check.Status
		}
	}

	switch {
	case coreFails >= 2:
		return "F", "Multiple core mail checks failed."
	case coreFails == 1 || coreWarns >= 2 || dkim == StatusFail:
		if firstCoreFail != "" {
			return "D", firstCoreFail + " failed."
		}
		if dkim == StatusFail {
			return "D", "DKIM check failed."
		}
		return "D", "Multiple core mail checks need attention."
	case coreWarns == 1:
		if firstCoreWarn == "DMARC" {
			if dkim == StatusPass {
				return "B", "DMARC is set to monitoring only."
			}
			return "C", "DMARC is monitoring only and DKIM could not be confirmed."
		}
		return "C", firstCoreWarn + " needs attention."
	case dkim == StatusPass:
		return "A", "Core mail records pass."
	default:
		return "B", "Core mail records pass; DKIM could not be confirmed from guessed selectors."
	}
}
