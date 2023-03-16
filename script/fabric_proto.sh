#!/bin/sh

PROTODIR=./server/fabric/protos
if [ -d $PROTODIR ]; then
    exit 0
fi

echo "Downloading proto files"
SRCPROTODIR=./server/fabric/srcprotos/
SRC_URL=https://raw.githubusercontent.com/hyperledger/fabric/v1.4.12/protos/

for i in `cat ./script/fabric.protos`; do
    dname=$SRCPROTODIR$(dirname $i)
    mkdir -p $dname

    filename=$dname/$(basename $i)
    echo $filename
    if [ -f $filename ]; then
        continue
    fi
    (cd $dname; wget $SRC_URL$i)
done

cd ./server/fabric
mkdir protos

opt_args='paths=source_relative Mmsp/msp_principal.proto=fabric/protos/msp'
srcs='srcprotos/common/common.proto srcprotos/common/policies.proto srcprotos/common/configuration.proto srcprotos/common/configtx.proto'
opts=''
for i in $opt_args; do
    opts="$opts --go_opt $i"
done
protoc -I ./srcprotos/ --go_out=./protos $opts $srcs
(cd protos/common; go mod init common)

opt_args='paths=source_relative'
opts=''
for i in $opt_args; do
    opts="$opts --go_opt $i"
done
srcs1='ledger/queryresult/kv_query_result.proto ledger/rwset/kvrwset/kv_rwset.proto ledger/rwset/rwset.proto'
srcs=''
for i in $srcs1; do
    srcs="$srcs srcprotos/$i"
done
protoc -I ./srcprotos/ --go_out=./protos $opts $srcs
(cd protos/ledger/queryresult; go mod init queryresult)
(cd protos/ledger/rwset; go mod init rwset)
(cd protos/ledger/rwset/kvrwset; go mod init kvrwset)

opt_args='paths=source_relative'
opts=''
for i in $opt_args; do
    opts="$opts --go_opt $i"
done
srcs1='msp/identities.proto msp/msp_config.proto msp/msp_principal.proto'
srcs=''
for i in $srcs1; do
    srcs="$srcs srcprotos/$i"
done
protoc -I ./srcprotos/ --go_out=./protos $opts $srcs
(cd protos/msp; go mod init msp)

opt_args='paths=source_relative Mcommon/common.proto=fabric/protos/common'
opts=''
for i in $opt_args; do
    opts="$opts --go_opt $i --go-grpc_opt $i"
done
srcs1='orderer/ab.proto orderer/configuration.proto'
srcs=''
for i in $srcs1; do
    srcs="$srcs srcprotos/$i"
done
protoc -I ./srcprotos/ --go_out=./protos --go-grpc_out=./protos $opts $srcs
(cd protos/orderer; go mod init orderer)

opt_args='paths=source_relative Mcommon/common.proto=fabric/protos/common Mtoken/expectations.proto=fabric/protos/token'
opts=''
for i in $opt_args; do
    opts="$opts --go_opt $i --go-grpc_opt $i"
done
srcs1='peer/chaincode_event.proto peer/chaincode.proto peer/configuration.proto peer/events.proto peer/peer.proto peer/proposal.proto peer/proposal_response.proto peer/query.proto peer/transaction.proto'
srcs=''
for i in $srcs1; do
    srcs="$srcs srcprotos/$i"
done
protoc -I ./srcprotos/ --go_out=./protos --go-grpc_out=./protos $opts $srcs
(cd protos/peer; go mod init peer)

opt_args='paths=source_relative'
opts=''
for i in $opt_args; do
    opts="$opts --go_opt $i"
done
srcs1='token/expectations.proto token/transaction.proto'
srcs=''
for i in $srcs1; do
    srcs="$srcs srcprotos/$i"
done
protoc -I ./srcprotos/ --go_out=./protos $opts $srcs
(cd protos/token; go mod init token)

mkdir -p srcprotos/shim
cp srcprotos/peer/chaincode_shim.proto srcprotos/shim
sed -ie 's@protos/peer@protos/shim@' srcprotos/shim/chaincode_shim.proto
srcs='srcprotos/shim/chaincode_shim.proto'
opt_args='paths=source_relative Mpeer/chaincode_event.proto=fabric/protos/peer Mpeer/proposal.proto=fabric/protos/peer'
opts=''
for i in $opt_args; do
  opts="$opts --go_opt $i --go-grpc_opt $i"
done
protoc -I ./srcprotos/ --go_out=./protos --go-grpc_out=./protos $opts $srcs
(cd protos/shim; go mod init shim)
