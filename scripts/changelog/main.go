package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type commitEntry struct {
	Subject string
}

type groupedEntry struct {
	Category string
	Text     string
}

var conventionalCommitPattern = regexp.MustCompile(`^([a-zA-Z]+)(\([^)]+\))?(!)?:\s*(.+)$`)

var categoryOrder = []string{
	"Features",
	"Fixes",
	"Performance",
	"Refactors",
	"Docs",
	"Tests",
	"CI",
	"Chores",
	"Other",
}

var categoryMap = map[string]string{
	"feat":     "Features",
	"fix":      "Fixes",
	"perf":     "Performance",
	"refactor": "Refactors",
	"docs":     "Docs",
	"doc":      "Docs",
	"test":     "Tests",
	"tests":    "Tests",
	"ci":       "CI",
	"chore":    "Chores",
}

func main() {
	var version string
	var previous string
	var target string
	var notesFile string
	var changelogFile string
	var date string

	flag.StringVar(&version, "version", "", "release version, for example v1.2.3")
	flag.StringVar(&previous, "previous", "", "previous release tag")
	flag.StringVar(&target, "target", "HEAD", "git ref or tag to generate notes for")
	flag.StringVar(&notesFile, "notes-file", "", "write release notes to this file")
	flag.StringVar(&changelogFile, "changelog-file", "", "update this changelog file")
	flag.StringVar(&date, "date", "", "release date in YYYY-MM-DD format")
	flag.Parse()

	if version == "" {
		fmt.Fprintln(os.Stderr, "error: --version is required")
		os.Exit(2)
	}

	if date == "" {
		date = time.Now().UTC().Format("2006-01-02")
	}

	commits, err := loadCommits(previous, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	section := renderSection(version, date, commits)
	releaseNotes := strings.TrimSpace(strings.TrimPrefix(section, fmt.Sprintf("## %s - %s\n\n", version, date))) + "\n"

	if notesFile != "" {
		if err := os.WriteFile(notesFile, []byte(releaseNotes), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing notes file: %v\n", err)
			os.Exit(1)
		}
	}

	if changelogFile != "" {
		if err := updateChangelog(changelogFile, version, section); err != nil {
			fmt.Fprintf(os.Stderr, "error updating changelog: %v\n", err)
			os.Exit(1)
		}
	}

	if notesFile == "" && changelogFile == "" {
		fmt.Print(releaseNotes)
	}
}

func loadCommits(previous string, target string) ([]commitEntry, error) {
	args := []string{"log", "--format=%s"}
	if previous != "" {
		args = append(args, previous+".."+target)
	} else {
		args = append(args, target)
	}

	output, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git log failed: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	commits := make([]commitEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		commits = append(commits, commitEntry{Subject: line})
	}

	return commits, nil
}

func renderSection(version string, date string, commits []commitEntry) string {
	grouped := groupCommits(commits)

	var builder strings.Builder
	fmt.Fprintf(&builder, "## %s - %s\n\n", version, date)

	if len(grouped) == 0 {
		builder.WriteString("### Other\n")
		builder.WriteString("- No user-facing changes recorded.\n")
		return builder.String()
	}

	for _, category := range categoryOrder {
		items := grouped[category]
		if len(items) == 0 {
			continue
		}

		fmt.Fprintf(&builder, "### %s\n", category)
		for _, item := range items {
			fmt.Fprintf(&builder, "- %s\n", item.Text)
		}

		builder.WriteString("\n")
	}

	return strings.TrimRight(builder.String(), "\n") + "\n"
}

func groupCommits(commits []commitEntry) map[string][]groupedEntry {
	grouped := make(map[string][]groupedEntry)

	for _, commit := range commits {
		category, text := classifyCommit(commit.Subject)
		grouped[category] = append(grouped[category], groupedEntry{
			Category: category,
			Text:     text,
		})
	}

	return grouped
}

func classifyCommit(subject string) (string, string) {
	match := conventionalCommitPattern.FindStringSubmatch(subject)
	if len(match) == 0 {
		return "Other", subject
	}

	kind := strings.ToLower(match[1])
	text := match[4]
	category, ok := categoryMap[kind]
	if !ok {
		category = "Other"
	}

	return category, text
}

func updateChangelog(path string, version string, section string) error {
	if existingVersion(path, version) {
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	header := "# Changelog\n\nAll notable changes to this project will be documented in this file.\n\n"
	if len(content) == 0 {
		return os.WriteFile(path, []byte(header+section), 0o644)
	}

	if !bytes.HasPrefix(content, []byte("# Changelog\n")) {
		content = append([]byte(header), content...)
	}

	firstSection := bytes.Index(content, []byte("\n## "))
	if firstSection == -1 {
		trimmed := strings.TrimRight(string(content), "\n")
		return os.WriteFile(path, []byte(trimmed+"\n\n"+section), 0o644)
	}

	prefix := content[:firstSection+1]
	rest := bytes.TrimLeft(content[firstSection+1:], "\n")
	updated := append([]byte{}, prefix...)
	updated = append(updated, []byte(section)...)
	updated = append(updated, '\n')
	updated = append(updated, rest...)

	return os.WriteFile(path, updated, 0o644)
}

func existingVersion(path string, version string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	return bytes.Contains(content, []byte("## "+version+" - "))
}
