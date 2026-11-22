// Package apiclient holds the typed HTTP client for the api listener, generated from
// spec/openapi.yaml for the cipherframe command line tool (ADR 0051). Do not edit client.gen.go;
// edit the spec and run `go generate ./...` (CI fails if the committed output is stale).
package apiclient

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2 -config cfg.yaml ../../spec/openapi.yaml
