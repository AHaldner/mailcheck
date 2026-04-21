package report

import (
	"encoding/json"

	"github.com/AHaldner/mailcheck/internal/model"
)

func RenderJSON(result model.RunResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
