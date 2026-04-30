// Package capi contains the pure-Go logic that backs the C ABI
// shared-library entry points in cmd/cshared/main.go. Splitting the
// logic out of the file that imports "C" lets the API surface be
// exercised by ordinary `go test` (no cgo, no -buildmode=c-shared
// dance) and keeps the C-bridge file thin.
//
// The package is internal and is consumed only by cmd/cshared/main.go
// (the //export wrappers) and the matching test file. External
// callers must go through the C ABI surface.
package capi
