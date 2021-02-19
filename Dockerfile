FROM ubuntu:20.10
MAINTAINER eiichiro.oiwa.nm@hitachi.com

RUN mkdir -p /var/lib/ImmutableST/bin
COPY ./tmpl /var/lib/ImmutableST/tmpl
WORKDIR /var/lib/ImmutableST/bin
COPY svc/immsSvc ./
COPY script/imms.sh ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/httpd/html
WORKDIR /var/lib/ImmutableST/tmpl/httpd/html
COPY ./web/immDS.wasm ./web/ImmutableDS.css ./web/index.html ./web/wasm_exec.js ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/immsrv
WORKDIR /var/lib/ImmutableST/tmpl/immsrv
COPY ./server/immsrv ./
COPY ./chaincode/hlRsyslog.tar.gz ./hlRsyslog

RUN mkdir -p /var/lib/ImmutableST/org

RUN apt-get update && apt-get install -y cpio  \
    && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["/var/lib/ImmutableST/bin/imms.sh", "start"]
WORKDIR /var/lib/ImmutableST/bin
