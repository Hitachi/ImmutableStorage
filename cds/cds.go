package main

import (
	"fmt"
//	"encoding/hex"
	"github.com/hyperledger/fabric/core/chaincode/platforms/golang"
	"io/ioutil"
)

func main() {
	pl := &golang.Platform{}


	cds, err := pl.GetDeploymentPayload("hlRsyslog/go")

	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	}
	
//	fmt.Printf("dump:\n %s\n", hex.Dump(cds))
	ioutil.WriteFile("hlRsyslog.tar.gz", cds, 0755)
}
	
