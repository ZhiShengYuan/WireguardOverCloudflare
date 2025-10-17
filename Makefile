.PHONY: run test tidy

run:
go run ./cmd/gateway

test:
go test ./...

tidy:
go mod tidy

