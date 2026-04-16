package server

import (
	"html/template"
	"io/fs"
	"strings"
)

// LoadTemplatesFS parses every *.html under root using io/fs. The function is
// fed an embedded FS by main; tests can pass a fstest.MapFS.
func LoadTemplatesFS(fsys fs.FS) (*template.Template, error) {
	root := template.New("").Funcs(template.FuncMap{
		"date": func(s string) string {
			// best-effort, nice-to-have formatter
			return s
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
	})

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".html") {
			return nil
		}
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		// Use only the basename so handlers reference "login.html" not "templates/login.html".
		name := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			name = path[i+1:]
		}
		_, err = root.New(name).Parse(string(raw))
		return err
	})
	if err != nil {
		return nil, err
	}
	return root, nil
}
