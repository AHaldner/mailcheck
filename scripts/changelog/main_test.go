package main

import (
	"os"
	"strings"
	"testing"
)

func TestClassifyCommitGroupsConventionalCommits(t *testing.T) {
	tests := []struct {
		subject  string
		category string
		text     string
	}{
		{subject: "feat: add version flag", category: "Features", text: "add version flag"},
		{subject: "fix(cli): parse timeout correctly", category: "Fixes", text: "parse timeout correctly"},
		{subject: "docs: shorten README", category: "Docs", text: "shorten README"},
		{subject: "random commit subject", category: "Other", text: "random commit subject"},
	}

	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			category, text := classifyCommit(tt.subject)
			if category != tt.category || text != tt.text {
				t.Fatalf("classifyCommit(%q) = (%q, %q), want (%q, %q)", tt.subject, category, text, tt.category, tt.text)
			}
		})
	}
}

func TestRenderSectionGroupsByCategory(t *testing.T) {
	section := renderSection("v1.2.3", "2026-04-21", []commitEntry{
		{Subject: "fix: handle resend helper host"},
		{Subject: "feat: add version flag"},
		{Subject: "docs: shorten README"},
	})

	for _, part := range []string{
		"## v1.2.3 - 2026-04-21",
		"### Features",
		"- add version flag",
		"### Fixes",
		"- handle resend helper host",
		"### Docs",
		"- shorten README",
	} {
		if !strings.Contains(section, part) {
			t.Fatalf("section missing %q:\n%s", part, section)
		}
	}
}

func TestUpdateChangelogPrependsNewSection(t *testing.T) {
	path := t.TempDir() + "/CHANGELOG.md"
	if err := os.WriteFile(path, []byte("# Changelog\n\nAll notable changes to this project will be documented in this file.\n\n## v1.0.0 - 2026-04-20\n\n### Features\n- first release\n"), 0o644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	section := "## v1.1.0 - 2026-04-21\n\n### Fixes\n- patch release\n"
	if err := updateChangelog(path, "v1.1.0", section); err != nil {
		t.Fatalf("updateChangelog error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	got := string(content)
	if !strings.Contains(got, "All notable changes to this project will be documented in this file.\n\n## v1.1.0 - 2026-04-21") {
		t.Fatalf("header and intro should stay before the new section:\n%s", got)
	}

	first := strings.Index(got, "## v1.1.0 - 2026-04-21")
	second := strings.Index(got, "## v1.0.0 - 2026-04-20")
	if first == -1 || second == -1 || first > second {
		t.Fatalf("new section was not prepended:\n%s", got)
	}
}
