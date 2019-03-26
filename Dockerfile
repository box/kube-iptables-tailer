FROM golang:1.11.5 as builder
WORKDIR $GOPATH/src/github.com/box/kube-iptables-tailer
COPY . $GOPATH/src/github.com/box/kube-iptables-tailer
RUN make build

FROM ubuntu
LABEL maintainer="Saifuding Diliyaer <sdiliyaer@box.com>"
WORKDIR /root/
COPY --from=builder /go/src/github.com/box/kube-iptables-tailer/kube-iptables-tailer /kube-iptables-tailer
