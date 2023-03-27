FROM golang:1.19.5-alpine3.17 AS builder1

ENV SRCDIR=./
ENV BUILDROOT=/builddir

WORKDIR $BUILDROOT
COPY $SRCDIR/ ./

# download proto files and generate codes
RUN apk add protoc protobuf protobuf-dev
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
RUN ./script/fabric_proto.sh

# build sources for the rsyslog image
ENV outdir=$BUILDROOT/out/rsyslog2imm
ENV buildsrc=$BUILDROOT/app/rsyslog2imm

WORKDIR $buildsrc
RUN CGO_ENABLED=0 GOOS=linux go build

RUN mkdir -p $outdir
RUN cp -p ./Dockerfile ./rsyslog2imm $outdir
RUN tar cvf $outdir/../rsyslog2imm.tar -C $outdir .

# build sources for the immpluginsrv image
ENV outdir=$BUILDROOT/out/immpluginsrv
ENV buildsrc=$BUILDROOT/server/immpluginsrv

WORKDIR $buildsrc/hlRsyslog
RUN CGO_ENABLED=0 GOOS=linux go build
WORKDIR $buildsrc
RUN CGO_ENABLED=0 GOOS=linux go build

RUN mkdir -p $outdir
RUN cp -p ./Dockerfile ./immpluginsrv ./hlRsyslog/hlRsyslog $outdir
RUN tar cvf $outdir/../immpluginsrv.tar -C $outdir .

# build sources for the GRPC proxy image
ENV outdir=$BUILDROOT/out/grpcProxy
ENV buildsrc=$BUILDROOT/server/grpcProxy

WORKDIR $buildsrc
RUN CGO_ENABLED=0 GOOS=linux go build

RUN mkdir -p $outdir
RUN cp -p ./Dockerfile ./grpcProxy $outdir
RUN tar cvf $outdir/../immgrpcproxy.tar -C $outdir .

# make sources for StackStorm authentication backend
ENV outdir=$BUILDROOT/out
ENV buildsrc=$BUILDROOT/client/st2-auth-backend
RUN tar cvf $outdir/st2-auth-backend.tar -C $buildsrc .

# build Immutable Storage server
FROM golang:1.19.5 AS builder2

ENV SRCDIR=./
ENV BUILDROOT=/builddir

RUN apt-get update && apt-get install -y brotli libbtrfs-dev libdevmapper-dev

WORKDIR $BUILDROOT
COPY $SRCDIR/ ./

COPY --from=builder1 /builddir/server/fabric/protos ./server/fabric/

WORKDIR $BUILDROOT/svc
RUN go build

WORKDIR $BUILDROOT/web
ENV WASM=immDS.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz
RUN cp -p $(go env GOROOT)/misc/wasm/wasm_exec.js .

WORKDIR $BUILDROOT/web/immex
ENV WASM=immex.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/web/oauth
ENV WASM=enrolluser.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/app/readWriteLog
ENV WASM=readWriteLog.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/app/secretBallot
ENV WASM=secretballot.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/app/anonymousSurvey
ENV WASM=anonymoussurvey.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/app/rsyslogconfig
ENV WASM=rsyslogconfig.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/app/workflow/general
ENV WASM=workflowweb.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

WORKDIR $BUILDROOT/app/workflow/admin
ENV WASM=workflowadminweb.wasm
RUN GOOS=js GOARCH=wasm go build && brotli -f $WASM && gzip --best -c $WASM > $WASM.gz

# make sources for a immsrv image
ENV outdir=$BUILDROOT/out/immsrv
RUN mkdir -p $outdir

WORKDIR $BUILDROOT/server
RUN go build

RUN mkdir -p /tmp/dummy
RUN echo "dummy" > /tmp/dummy/dummy
RUN tar cvzf $outdir/hlRsyslog -C /tmp ./dummy # make a dummy chaincode
RUN cp -p ./Dockerfile ./immsrv $outdir/
RUN tar cvf $outdir/../immsrv.tar -C $outdir .


FROM ubuntu:22.04
MAINTAINER eiichiro.oiwa.nm@hitachi.com

ENV BUILDROOT=/builddir

ENV DSTDIR=/var/lib/ImmutableST
RUN mkdir -p $DSTDIR

# copy configuration templates
ENV SRCDIR=$BUILDROOT/tmpl
RUN mkdir -p $DSTDIR/tmpl
WORKDIR $DSTDIR/tmpl
COPY --from=builder1 $SRCDIR .

RUN mkdir -p $DSTDIR/bin
WORKDIR $DSTDIR/bin

COPY --from=builder2 $BUILDROOT/svc/immsSvc ./
COPY --from=builder2 $BUILDROOT/script/imms.sh $BUILDROOT/script/remount_cgroup.sh ./

RUN mkdir -p $DSTDIR/tmpl/httpd/html
WORKDIR $DSTDIR/tmpl/httpd/html

ENV SRCDIR=$BUILDROOT/web
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html $SRCDIR/*.css $SRCDIR/*.js ./

ENV SRCDIR=$BUILDROOT/web/immex
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz ./

ENV SRCDIR=$BUILDROOT/web/oauth
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz ./

ENV SRCDIR=$BUILDROOT/app/readWriteLog
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html ./

ENV SRCDIR=$BUILDROOT/app/secretBallot
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html ./

ENV SRCDIR=$BUILDROOT/app/anonymousSurvey
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html ./

ENV SRCDIR=$BUILDROOT/app/rsyslogconfig
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html ./


RUN mkdir -p $DSTDIR/tmpl/httpd/html/st2web
WORKDIR $DSTDIR/tmpl/httpd/html/st2web

ENV SRCDIR=$BUILDROOT/app/workflow/general
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html ./

ENV SRCDIR=$BUILDROOT/app/workflow/admin
COPY --from=builder2 $SRCDIR/*.wasm.br $SRCDIR/*.wasm.gz $SRCDIR/*.html ./
RUN ln -s workflow.html index.html && ln -s workflow.html st2login.html && ln -s ../wasm_exec.js . && ln -s ../*.css .


ENV SRCDIR=$BUILDROOT/out
RUN mkdir -p $DSTDIR/imgsrc
WORKDIR $DSTDIR/imgsrc
COPY --from=builder1 $SRCDIR/*.tar ./
COPY --from=builder2 $SRCDIR/*.tar ./

RUN apt-get update
RUN apt-get install -y cpio
RUN apt-get install -y ca-certificates
RUN apt-get install -y libdevmapper1.02.1
RUN apt-get install -y runc
RUN rm -rf /var/lib/apt/lists/*

CMD ["$DSTDIR/bin/imms.sh", "start"]

RUN mkdir -p $DSTDIR/org
WORKDIR $DSTDIR/bin
