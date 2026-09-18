package web

import "embed"

//go:embed index.html css/* js/*
var StaticFS embed.FS
