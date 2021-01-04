/*
Copyright Hitachi, Ltd. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libimmds.h>

int
main(int ac, char *av[]){
    char *keyDir;
    char *username;
    char *storageGrp;
    char *logData = 0;

    if (ac < 5) {
        printf("Usage: %s key-directory username {read|write} storage-group [write-log]\n", av[0]);
        return 50;
    }
    keyDir = av[1];
    username = av[2];
    char *op = av[3]; // operation {read|write}
    storageGrp = av[4];

    if ( (strcmp(op, "write") != 0) && (strcmp(op, "read") != 0) ) {
        printf("unsupported operation: %s\n", op);
        printf("Usage: %s key-directory username {read|write} storage-group [write-log]\n", av[0]);
        return 51;
    }
    if (strcmp(op, "write") == 0) {
        if (ac != 6) {
            printf("Usage: %s key-directory username write storage-group write-log\n", av[0]);
            return 52;
        }

        logData = av[5];
    }
    
    struct OpenKey_return id;
    id = OpenKey(username, keyDir, 0);
    if(id.r1 != 0){
        printf("error: %s\n", id.r1);
        free(id.r1);
        return 1;
    }

    if (strcmp(op, "write") == 0) {
        char *err;
        err = RecordImmData(id.r0, storageGrp, "logC", logData);
        if(err != 0){
            printf("error: RecordImmData: %s\n", err);
            free(err);
            return 2;
        }

        return 0; // success
    }

    // load immutable data
    struct GetTxID_return rsp = GetTxID(id.r0, storageGrp, "logC");
    if(rsp.r1 != 0){
        printf("error: %s\n", rsp.r1);
        free(rsp.r1);
        return 3;
    }

    struct GetBlockByTxID_return blockRet;
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

        blockRet = GetBlockByTxID(id.r0, storageGrp, TxID);
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
