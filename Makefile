all: fmt vet

fmt:
	go fmt ./...

vet:
	go vet ./...
