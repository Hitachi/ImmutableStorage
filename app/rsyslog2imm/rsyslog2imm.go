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

package main

import (
	//	"time"
	"fmt"
	"os"
	"strings"
	"encoding/hex"
	"immledger"
)

const (
	defaultConfigFile = "/etc/rsyslog2imm/config.yaml"
	defaultUserName = "rec2@example.com"
	defaultKeyPath = "/etc/rsyslog2imm"
	defaultStorageGrp = "storage-grp"
)

func main() {
	cfg := &immledger.ImmCfg{
		UserName: defaultUserName,
		KeyPath: defaultKeyPath,
		StorageGroup: defaultStorageGrp,
	}
	
	if len(os.Args) != 2 {
		print("invalid arguments\n")
		return
	}

	finfo, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if finfo.Mode() & os.ModeNamedPipe == 0 {
		fmt.Printf("error: not named pipe\n")
		os.Exit(3)
	}
	
	logFormat := os.Args[1]

	if logFormat != "TraditionalFormat" {
		fmt.Printf("%s is unsupported\n", logFormat)
		os.Exit(10)
	}

	buf := make([]byte, 1024)
	logLen, err := os.Stdin.Read(buf)
	if err != nil {
		fmt.Printf("read error: %s\n", err)
		os.Exit(4)
	}
	buf = buf[:logLen]

	const timeFmt = "Jan 02 15:04:05"
	hostnameP := len(timeFmt)+1
	hostProgMsg := buf[hostnameP:]
	strs := strings.Split(string(hostProgMsg), ":")
	strs = strings.Split(strs[0], " ")
	//	hostname := strs[0]
	
	progName := []byte(strs[1])
	progTail := len(progName)
	for i, ch := range progName {
		if ch == '[' {
			progTail = i
			break;
		}
	}
	progNameShort := progName[:progTail]

	print("progNameShort=" + string(progNameShort) + ", logFormat=" + string(logFormat) + "\n")

	//	print("UserName: " + cfg.UserName + ", KeyPath: " + cfg.KeyPath + ", Password: " + cfg.Password + "\n")
	
	print(hex.Dump(buf))
	ledger, err := immledger.OpenKeyWithDefault(defaultConfigFile, cfg)
	if err != nil {
		print("could not open keys: " + err.Error() + "\n")
		os.Exit(5)
	}

	ledger.Write("", string(progNameShort), string(buf))
}
