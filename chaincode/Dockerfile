FROM golang:1.17.6
RUN mkdir -p /chaincode/input
RUN mkdir -p /chaincode/output

COPY hlRsyslog /usr/local/go/src/hlRsyslog
COPY immplugin /usr/local/go/src/immplugin
WORKDIR /usr/local/go/src/hlRsyslog/go
RUN go build -ldflags "-linkmode external -extldflags '-static'" -o /chaincode/output/chaincode hlRsyslog/go
