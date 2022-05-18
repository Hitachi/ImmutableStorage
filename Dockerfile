FROM ubuntu:20.04
MAINTAINER eiichiro.oiwa.nm@hitachi.com

RUN mkdir -p /var/lib/ImmutableST/bin
COPY ./tmpl /var/lib/ImmutableST/tmpl
WORKDIR /var/lib/ImmutableST/bin
COPY svc/immsSvc ./
COPY script/imms.sh script/remount_cgroup.sh ./

RUN mkdir -p /var/lib/ImmutableST/tmpl/httpd/html
WORKDIR /var/lib/ImmutableST/tmpl/httpd/html
COPY ./web/immDS.wasm.br ./web/immDS.wasm.gz ./web/ImmutableDS.css ./web/index.html ./web/wasm_exec.js ./
COPY ./web/immex/immex.wasm.br ./web/immex/immex.wasm.gz ./
COPY ./web/oauth/enrolluser.wasm.br ./web/oauth/enrolluser.wasm.gz ./web/oauth/enrolluser.wasm.gz ./

COPY ./app/readWriteLog/readWriteLog.html ./app/readWriteLog/readWriteLog.wasm.br ./app/readWriteLog/readWriteLog.wasm.gz ./ 
COPY ./app/secretBallot/secretBallot.html ./app/secretBallot/secretballot.wasm.br ./app/secretBallot/secretballot.wasm.gz ./
COPY ./app/anonymousSurvey/anonymousSurvey.html ./app/anonymousSurvey/anonymoussurvey.wasm.br ./app/anonymousSurvey/anonymoussurvey.wasm.gz ./

WORKDIR /var/lib/ImmutableST/tmpl/immsrv
COPY ./server/immsrv ./
COPY ./chaincode/hlRsyslog.tar.gz ./hlRsyslog

RUN mkdir -p /var/lib/ImmutableST/immplugin
WORKDIR /var/lib/ImmutableST/immplugin
COPY ./chaincode/hlRsyslog/go/hlRsyslog ./
COPY ./server/immpluginsrv/immpluginsrv ./

RUN mkdir -p /var/lib/ImmutableST/org

RUN apt-get update
RUN apt-get install -y cpio
RUN apt-get install -y ca-certificates
RUN apt-get install -y libdevmapper1.02.1
RUN apt-get install -y runc
RUN rm -rf /var/lib/apt/lists/*

CMD ["/var/lib/ImmutableST/bin/imms.sh", "start"]
WORKDIR /var/lib/ImmutableST/bin
