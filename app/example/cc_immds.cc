#include <iostream>
#include <string>
#include <cstdlib>
#include "../libimmds/libimmds.h"
#include "../libimmds/libimmds.pb.h"
#include <common/common.pb.h>
#include <peer/transaction.pb.h>
#include <peer/proposal.pb.h>
#include <peer/chaincode.pb.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>

std::string
getPassword(std::string prompt){
    std::string passBuf;
    int ch;

    std::cout << "Please enter the password: ";
    struct termios  saveTermAttr, noechoAttr;
    tcgetattr(STDIN_FILENO, &saveTermAttr);
    noechoAttr = saveTermAttr;
    noechoAttr.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &noechoAttr);

    for(;(ch = getchar()) != 0x0a /*line feed*/;){
        if( ((ch == 0x7f /* delete */) || (ch == 0x08 /* backspace */)) && (passBuf.length() > 0) ){
            passBuf.resize(passBuf.length() - 1);
            continue;
        }

        if(ch == 0x15 /*Negative Acknowledgement*/){
            passBuf.resize(0);
            continue;
        }
        
        passBuf += ch;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &saveTermAttr);
    std::cout << std::endl;
    
    return passBuf;
}

int
main(int, char **){
    char *username = (char *)"user1";
    char *storageGrp = (char *)"storage-grp";
    OpenKey_return id;
    std::string passBuf;

    passBuf = getPassword("Please enter the password: ");
    
    id = OpenKey(username, (char *)"/home/k8/Downloads", (char *)passBuf.c_str());
    if(id.r1 != 0){
        std::cerr << "error: " << id.r1 << "\n";
        std::free(id.r1);
        return 1;
    }

#if 0 /// record ledger
    char *err;
    err = RecordLedger(id.r0, storageGrp, (char*)"logC", (char*)"1234567890");
    if(err != 0){
        printf("error: RecordLedger: %s\n", err);
        free(err);
        return 2;
    }
#endif// record ledger


    struct GetTxIDOnLedger_return rsp = GetTxIDOnLedger(id.r0, storageGrp, (char*)"logC");
    if(rsp.r1 != 0){
        std::cerr << "error: " << rsp.r1 << "\n";
        std::free(rsp.r1);
        return 3;
    }

    libimmds::TxIdList list;
    list.ParseFromString(std::string(rsp.r0));
    std::free(rsp.r0);

    struct QueryBlockByTxID_return blockRet;
    std::cout << "number of ids = " << list.txid_size() << "\n";
    for(int i = 0; i < list.txid_size(); i++){
        std::cout << "TxID: " << list.txid(i) << "\n";

        blockRet = QueryBlockByTxID(id.r0, storageGrp, (char*)list.txid(i).c_str());
        if(blockRet.r2 != 0){
            std::cerr << "error: " << blockRet.r2 << "\n";
            std::free(blockRet.r2);
        }

        common::Block blockSt;
        blockSt.ParseFromString(std::string(blockRet.r0, blockRet.r1));
        std::free(blockRet.r0);
        std::cout << "block size=" << blockRet.r1 << "\n";

        if( !blockSt.has_data() )
            continue;
        
        common::ChannelHeader channelHeaderSt;
        protos::Transaction transactionSt;
        bool foundTxIdF = false;
        for(int j = 0; j < blockSt.data().data_size(); j++){
            common::Envelope envelopeSt;
            if( !envelopeSt.ParseFromString(blockSt.data().data(j)) ){
                std::cerr << "error: failed to parse the blockData\n";
                return 10;
            }
            common::Payload payloadSt;
            if( !payloadSt.ParseFromString(envelopeSt.payload()) ){
                std::cerr << "error: failed to parse a payload\n";
                return 11;
            }
            if( !payloadSt.has_header() ){
                std::cerr << "error: unexpected payload format\n";
                return 12;
            }
            
            if( !channelHeaderSt.ParseFromString(payloadSt.header().channel_header()) ){
                std::cerr << "error: failed to parse a channel-header\n";
                return 13;
            }

            foundTxIdF = (list.txid(i) == channelHeaderSt.tx_id());
            if(foundTxIdF){
                if( !transactionSt.ParseFromString(payloadSt.data()) ){
                    std::cerr << "error: failed to parse a transaction\n";
                    return 14;
                }

                break;
            }
        }

        if(!foundTxIdF) {
            std::cerr << "error: not found TxID: " << list.txid(i) << "\n";
            return 4;
        }

        if( !channelHeaderSt.has_timestamp() )
            continue;

        time_t recordTimeSec = (time_t)channelHeaderSt.timestamp().seconds();
        struct tm *recordTm = localtime(&recordTimeSec);
        char tmBuf[256];
        strftime(tmBuf, sizeof(tmBuf), "%Y/%m/%d %H:%m:%S", recordTm);

        if( transactionSt.actions_size() != 1 ){
            std::cerr << "error: unexpected number of actions\n";
            return 20;
        }

        protos::ChaincodeActionPayload chaincodeActionPayloadSt;
        if( !chaincodeActionPayloadSt.ParseFromString(transactionSt.actions(0).payload()) ){
            std::cerr << "error: failed to parse a ChaincodeActionPayload\n";
            return 21;
        }

        protos::ChaincodeProposalPayload chaincodeProposalPayloadSt;
        if( !chaincodeProposalPayloadSt.ParseFromString(chaincodeActionPayloadSt.chaincode_proposal_payload()) ){
            std::cerr << "error: failed to parse a ChaincodeProposalPayload\n";
            return 22;
        }

        protos::ChaincodeInvocationSpec chaincodeInvocationSpecSt;
        if( !chaincodeInvocationSpecSt.ParseFromString(chaincodeProposalPayloadSt.input())){
            std::cerr << "error: failed to parse a ChaincodeInvocationSpec\n";
            return 23;
        }
        if( !chaincodeInvocationSpecSt.has_chaincode_spec() ){
            std::cerr << "error: unexpected ChaincodeInvocationSpec\n";
            return 24;
        }
        if( !chaincodeInvocationSpecSt.chaincode_spec().has_input() ){
            std::cerr << "error: unexected ChaincodeSpec\n";
            return 25;
        }

        protos::ChaincodeInput chainIn = chaincodeInvocationSpecSt.chaincode_spec().input();
        if(chainIn.args_size() != 4){
            std::cerr << "error: unexected log format\n";
            return 26;
        }
        std::printf("%s.%09d | %s | %s\n", tmBuf, channelHeaderSt.timestamp().nanos(), chainIn.args(1).c_str(), chainIn.args(3).c_str() );
    }
    
    return 0;
}
