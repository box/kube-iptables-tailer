all: build

ENVVAR = GOOS=linux GOARCH=amd64
TAG = v0.1.0
APP_NAME = kube-iptables-tailer

clean:
	rm -f $(APP_NAME)

fmt:
	find . -path ./vendor -prune -o -name '*.go' -print | xargs -L 1 -I % gofmt -s -w %

build-cgo: clean fmt
	$(ENVVAR) CGO_ENABLED=1 go build -mod vendor -o $(APP_NAME)

build: clean fmt
	$(ENVVAR) CGO_ENABLED=0 go build -mod vendor -o $(APP_NAME)

test-unit: clean deps fmt build
	CGO_ENABLED=0 go test -v -cover ./...

# Make the container using docker multi-stage build process
# So you don't necessarily have to install golang to make the container
container:
	docker build -f Dockerfile -t $(APP_NAME):$(TAG) .

container-cgo:
	docker build -f Dockerfile-cgo -t $(APP_NAME):$(TAG) .

.PHONY: all clean deps fmt build test-unit container
