FROM golang:1.15 as builder
WORKDIR $GOPATH/src/github.com/box/kube-iptables-tailer
COPY . $GOPATH/src/github.com/box/kube-iptables-tailer
RUN make build

FROM alpine
LABEL maintainer="Box OSS <oss@box.com>"
WORKDIR /root/
RUN apk --update add iptables
COPY --from=builder /go/src/github.com/box/kube-iptables-tailer/kube-iptables-tailer /kube-iptables-tailer
