FROM ubuntu:20.10
MAINTAINER eiichiro.oiwa.nm@hitachi.com

RUN mkdir -p /var/lib/ImmutableST/bin
COPY ./tmpl /var/lib/ImmutableST/tmpl
WORKDIR /var/lib/ImmutableST/bin
COPY svc/caSvcK8s/caSvc svc/httpSvcK8s/httpSvc svc/immSvcK8s/immSvc svc/preloadImg/preloadImg ./
COPY script/imms.sh ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/httpd/html
WORKDIR /var/lib/ImmutableST/tmpl/httpd/html
COPY ./web/immDS.wasm ./web/ImmutableDS.css ./web/index.html ./web/wasm_exec.js ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/immsrv
WORKDIR /var/lib/ImmutableST/tmpl/immsrv
COPY ./server/immsrv ./
COPY ./chaincode/hlRsyslog.tar.gz ./hlRsyslog

RUN mkdir -p /var/lib/ImmutableST/org

CMD ["imms.sh start"]
