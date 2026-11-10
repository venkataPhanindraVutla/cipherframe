// Package gen holds the code generated from spec/openapi.yaml for the edge listener: models, the
// strict server interface and the net/http routing glue. Do not edit edge.gen.go; edit the spec and
// run `go generate ./...` (CI fails if the committed output is stale).
package gen

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2 -config cfg.yaml ../../../spec/openapi.yaml
