package ui

import (
	"fmt"
	"io"
	"os"
)

type ProgressWriter struct {
	writer  io.Writer
	enabled bool
	color   bool
	active  bool
}

func NewProgressWriter(writer io.Writer, allow bool, color bool) *ProgressWriter {
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
	}
}

func (p *ProgressWriter) Start(name string) {
	if !p.enabled {
		return
	}

	label := "Checking " + name + "..."
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
