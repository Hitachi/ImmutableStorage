FROM ubuntu:20.04

RUN apt-get update  \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /chaincode/input
RUN mkdir -p /chaincode/output
COPY ./chaincode /chaincode/output/chaincode

RUN ln -s /bin/true /usr/bin/go
RUN ln -s /chaincode/output/chaincode /usr/local/bin/chaincode
