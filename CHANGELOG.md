# Changelog

All notable changes to this project will be documented in this file.

## v1.2.0 - 2026-04-24

### Features
- implement caching and goroutines
- implement better DNS resolver and more detailed flags

### Fixes
- handle null MX records and update DKIM selector candidates

### Docs
- update changelog for v1.1.2

### Other
- Merge pull request #1 from AHaldner/codex-mail-reliability-diagnostics

## v1.1.2 - 2026-04-22

### Features
- add help command and shorthand flags

### Fixes
- improve user feedback strings

### Refactors
- move duplicate functions into helper functions

### CI
- add test and changelog workflow

## v1.1.1 - 2026-04-21

### Fixes
- update passed version number style

## v1.1.0 - 2026-04-21

### Features
- add version flag to check current version
- implement a progress indicator
- add windows install support

### Fixes
- update goreleaser to avoid deprecations

### CI
- update release workflow to use latest actions and GoReleaser install

## v1.0.0 - 2026-04-21

### Features
- implement release workflow

### Chores
- add license
- initial commit
