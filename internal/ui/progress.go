package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const progressBarWidth = 20

type ProgressWriter struct {
	writer  io.Writer
	enabled bool
	color   bool
	active  bool
	total   int
	current int
}

func NewProgressWriter(writer io.Writer, allow bool, color bool, total int) *ProgressWriter {
	file, ok := writer.(*os.File)
	if !ok {
		return &ProgressWriter{}
	}

	info, err := file.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) == 0 {
		return &ProgressWriter{}
	}

	return &ProgressWriter{
		writer:  writer,
		enabled: allow,
		color:   color,
		total:   total,
	}
}

func (p *ProgressWriter) Start(name string) {
	if !p.enabled {
		return
	}

	if p.total <= 0 {
		p.total = 1
	}
	if p.current < p.total {
		p.current++
	}

	label := fmt.Sprintf("%s %d/%d %s", progressBar(p.current, p.total), p.current, p.total, name)
	if p.color {
		label = "\x1b[36m" + label + "\x1b[0m"
	}

	fmt.Fprintf(p.writer, "\r\x1b[2K%s", label)
	p.active = true
}

func (p *ProgressWriter) Finish() {
	if !p.enabled || !p.active {
		return
	}

	fmt.Fprint(p.writer, "\r\x1b[2K\n")
	p.active = false
}

func progressBar(current int, total int) string {
	if total <= 0 {
		total = 1
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}

	filled := current * progressBarWidth / total
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", progressBarWidth-filled) + "]"
}
