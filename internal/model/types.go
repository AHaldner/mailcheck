package model

type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
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
	Checks             []CheckResult `json:"checks"`
	DKIMSelectorsTried []string      `json:"dkimSelectorsTried,omitempty"`
	DKIMSelectorsFound []string      `json:"dkimSelectorsFound,omitempty"`
}

func RatingFromChecks(checks []CheckResult) string {
	var coreWarns int
	var coreFails int
	dkim := StatusWarn

	for _, check := range checks {
		switch check.Name {
		case "MX", "SPF", "DMARC":
			switch check.Status {
			case StatusWarn:
				coreWarns++
			case StatusFail:
				coreFails++
			}
		case "DKIM":
			dkim = check.Status
		}
	}

	switch {
	case coreFails >= 2:
		return "F"
	case coreFails == 1 || coreWarns >= 2 || dkim == StatusFail:
		return "D"
	case coreWarns == 1:
		return "C"
	case dkim == StatusPass:
		return "A"
	default:
		return "B"
	}
}
