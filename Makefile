all: build

ENVVAR = GOOS=linux GOARCH=amd64 CGO_ENABLED=0
TAG = v0.1.0
GODEP_BIN = $$GOPATH/bin/godep
APP_NAME = kube-iptables-tailer

clean:
	rm -f $(APP_NAME)

deps:
	go get github.com/tools/godep

fmt:
	find . -path ./vendor -prune -o -name '*.go' -print | xargs -L 1 -I % gofmt -s -w %

build: clean deps fmt
	$(ENVVAR) $(GODEP_BIN) go build -o $(APP_NAME)

test-unit: clean deps fmt build
	$(GODEP_BIN) go test -v -cover ./...

# Make the container using docker multi-stage build process
# So you don't necessarily have to install golang to make the container
container:
	docker build -t $(APP_NAME):$(TAG) .

.PHONY: all clean deps fmt build test-unit container