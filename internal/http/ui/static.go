// Package ui implements the management UI session API.
// This file provides the embedded static assets serving for the UI shell.
// Per system-architecture.md section 8 and implementation-roadmap.md Phase 5.
package ui

import (
	"embed"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

// content embeds the web/ directory contents.
// The directive must be in the package that declares the variable,
// and it must be a //go:embed comment directly before the var.
//
//go:embed all:static_embed
var content embed.FS

// staticFS is the filesystem rooted at web/ for serving.
var staticFS fs.FS

func init() {
	var err error
	staticFS, err = fs.Sub(content, "static_embed")
	if err != nil {
		panic("failed to create sub-filesystem for static assets: " + err.Error())
	}
}

// staticFileServer returns an http.Handler that serves embedded static files.
// It serves:
//   - /ui/ → index.html (SPA shell)
//   - /ui/static/* → static assets (CSS, JS)
//
// For API routes, this handler should not be reached (they're registered with higher priority).
// For unknown paths under /ui/, this returns the SPA shell so client-side routing can work.
func staticFileServer() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Strip /ui/ prefix to get the relative path
		relPath := strings.TrimPrefix(path, "/ui/")
		if relPath == "" || relPath == "/" {
			relPath = "index.html"
		}

		// For /ui/static/* paths, try to serve the file directly
		if strings.HasPrefix(relPath, "static/") {
			serveFile(w, r, relPath)
			return
		}

		// For all other /ui/* paths (non-API), serve index.html
		// This enables client-side routing for the SPA
		serveFile(w, r, "index.html")
	})
}

// serveFile reads and serves a file from the embedded filesystem.
func serveFile(w http.ResponseWriter, r *http.Request, filePath string) {
	f, err := staticFS.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	// Get file info for Content-Length
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Set Content-Type based on file extension
	ext := filepath.Ext(filePath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// For better caching of static assets
	if strings.HasPrefix(filePath, "static/") {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}

	// Read seeker for http.ServeContent
	if seeker, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, filePath, stat.ModTime(), seeker)
	} else {
		// Fallback: read entire file and write
		data, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
}

