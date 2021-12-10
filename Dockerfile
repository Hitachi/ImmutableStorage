FROM ubuntu:20.04
MAINTAINER eiichiro.oiwa.nm@hitachi.com

RUN mkdir -p /var/lib/ImmutableST/bin
COPY ./tmpl /var/lib/ImmutableST/tmpl
WORKDIR /var/lib/ImmutableST/bin
COPY svc/immsSvc ./
COPY script/imms.sh ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/httpd/html
WORKDIR /var/lib/ImmutableST/tmpl/httpd/html
COPY ./web/immDS.wasm.br ./web/immDS.wasm.gz ./web/ImmutableDS.css ./web/index.html ./web/wasm_exec.js ./
COPY ./web/immex/immex.wasm.br ./web/immex/immex.wasm.gz ./
COPY ./app/secretBallot/secretBallot.html ./app/secretBallot/secretballot.wasm.br ./app/secretBallot/secretballot.wasm.gz ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/immsrv/immplugin
WORKDIR /var/lib/ImmutableST/tmpl/immsrv
COPY ./server/immsrv ./
COPY ./chaincode/hlRsyslog.tar.gz ./hlRsyslog
COPY ./server/immpluginsrv/immpluginsrv ./immplugin/

RUN mkdir -p /var/lib/ImmutableST/org

RUN apt-get update && apt-get install -y cpio  \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["/var/lib/ImmutableST/bin/imms.sh", "start"]
WORKDIR /var/lib/ImmutableST/bin
