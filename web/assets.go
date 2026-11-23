// Package web holds the admin pages, served from the binary.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html mohur.css admin.mjs favicon.svg schibsted-grotesk.woff2
var files embed.FS

// Page is the one admin document.
func Page() []byte {
	b, err := files.ReadFile("index.html")
	if err != nil {
		panic(err)
	}
	return b
}

// Assets serves the stylesheet, script, icon and font.
func Assets() http.Handler {
	sub, err := fs.Sub(files, ".")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "index.html" || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
