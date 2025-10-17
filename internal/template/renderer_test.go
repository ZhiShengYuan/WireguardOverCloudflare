package template

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRendererRender(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tpl.json.tmpl")
	content := `{"value":"{{ .Value }}"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	renderer, err := NewRenderer(path)
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}

	out, err := renderer.Render(map[string]string{"Value": "hello"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	expected := `{"value":"hello"}`
	if out != expected {
		t.Fatalf("expected %s, got %s", expected, out)
	}
}
