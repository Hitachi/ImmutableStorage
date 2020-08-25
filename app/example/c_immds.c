#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../libimmds/libimmds.h"

int
main(){
    char *username = "user1";
    char *storageGrp = "storage-grp";
    
    struct OpenKey_return id;
    id = OpenKey(username, "/home/k8/Downloads", 0);
    if(id.r1 != 0){
        printf("error: %s\n", id.r1);
        free(id.r1);
        return 1;
    }

#if 0 // record log
    char *err;
    err = RecordLedger(id.r0, storageGrp, "logC", "Hi, ledger");
    if(err != 0){
        printf("error: RecordLedger: %s\n", err);
        free(err);
        return 2;
    }
#endif // record log

    struct GetTxIDOnLedger_return rsp = GetTxIDOnLedger(id.r0, storageGrp, "logC");
    if(rsp.r1 != 0){
        printf("error: %s\n", rsp.r1);
        free(rsp.r1);
        return 3;
    }

    struct QueryBlockByTxID_return blockRet;
    char TxID[0x40+1];
    char *protoP = rsp.r0;

    // decode protobuf
    for(; *protoP != 0; protoP += 0x40){
        if( *protoP != ((0x1/*field*/ << 3) | 2 /*Length-delimited*/)){
            printf("error: unexpected field in a response: 0x%02x\n", *protoP);
            free(rsp.r0);
            return 4;
        }
        protoP++;
        if( *protoP != 0x40 /* the lenght of TxID */){
            printf("error: unexpected the lenght of TxID: %d\n", *protoP);
            free(rsp.r0);
            return 5;
        }
        protoP++;

        memcpy(TxID, protoP, 0x40);
        TxID[0x40] = 0;
        printf("TxID: %s\n", TxID);

        blockRet = QueryBlockByTxID(id.r0, storageGrp, TxID);
        if(blockRet.r2 != 0){
            printf("error: %s\n", blockRet.r2);
            free(rsp.r0);
            free(blockRet.r2);
            return 6;
        }

        // parse block
        for(int i = 0; i < 10; i++){
            printf("%02x ", (unsigned char)*(blockRet.r0+i));
        }
        printf("\n");
        
        free(blockRet.r0);
    }
    
    free(rsp.r0);
    return 0;
}
