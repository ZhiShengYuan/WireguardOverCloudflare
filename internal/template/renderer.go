package template

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"text/template"
)

// Renderer wraps a text template for rendering JSON responses.
type Renderer struct {
	mu      sync.RWMutex
	tpl     *template.Template
	tplPath string
}

// NewRenderer loads a template from the given path.
func NewRenderer(path string) (*Renderer, error) {
	r := &Renderer{tplPath: path}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Render executes the template using the provided data.
func (r *Renderer) Render(data any) (string, error) {
	r.mu.RLock()
	tpl := r.tpl
	r.mu.RUnlock()

	if tpl == nil {
		return "", fmt.Errorf("template not loaded")
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Reload reloads the template from disk.
func (r *Renderer) Reload() error {
	return r.reload()
}

func (r *Renderer) reload() error {
	content, err := os.ReadFile(r.tplPath)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	tpl, err := template.New(filepath.Base(r.tplPath)).Parse(string(content))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tpl = tpl
	return nil
}
