/*
Copyright Hitachi, Ltd. 2021 All Rights Reserved.

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

package main

import (
	"strings"
	"fmt"
	"os"
	"golang.org/x/term"
	
	"immledger"
	"immblock"
)
	
func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s program-name config-file\n", os.Args[0])
		os.Exit(1)
	}

	progName := os.Args[1]
	cfgFile := os.Args[2]

	var ledger *immledger.ImmLedger
	var err error
	password := ""
	for i := 0; i < 5; i++ {
		ledger, err = immledger.OpenKeyWithCfgFile("", "", password, cfgFile)
		if  err == nil {
			break // success
		}

		if i == 4 {
			fmt.Printf("failed to open a key-pair: " + err.Error())
			os.Exit(2)
		}

		if strings.HasPrefix(err.Error(), immledger.ERR_PASS_INCORRECT) {
			fmt.Printf("Please enter the password: ")
			passwordByte, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Printf("\n")
			if err != nil {
				fmt.Printf("failed to read a password: %s\n", err)
				os.Exit(3)
			}
			password = string(passwordByte)
			continue
		}

		// error
		fmt.Printf("failed to opend a key-pair: " + err.Error())
		os.Exit(4)
	}

	txIDs, err := ledger.GetTxID("", progName)
	if err != nil {
		fmt.Printf("failed to read a ledger\n", err)
		os.Exit(5)
	}

	immblock.LB = "\n"	
	for _, txID := range txIDs {
		block, err := ledger.GetBlockByTxID("", txID)
		str, err := immblock.ReadBlock(block)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(6)
		}
		fmt.Printf(str)
	}
}
