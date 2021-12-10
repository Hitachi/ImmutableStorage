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
	"io"
	"strings"
	//"encoding/hex"
	"immledger"
)

const (
	defaultConfigFile = "/etc/rsyslog2imm/config.yaml"
	defaultUserName = "rec2@example.com"
	defaultKeyPath = "/etc/rsyslog2imm"
	defaultStorageGrp = "storage-grp"
)

func main() {
	if len(os.Args) < 2 {
		print("invalid argument\n")
		os.Exit(1)
	}

	finfo, err := os.Stdin.Stat()
	if err != nil {
		fmt.Printf("failed to get a message: %s\n", err)
		os.Exit(2)
	}

	if finfo.Mode() & os.ModeNamedPipe == 0 {
		fmt.Printf("error: not named pipe\n")
		os.Exit(3)
	}

	cfg := &immledger.ImmCfg{
		UserName: defaultUserName,
		KeyPath: defaultKeyPath,
		StorageGroup: defaultStorageGrp,
	}
	ledger, err := immledger.OpenKeyWithDefault(defaultConfigFile, cfg)
	if err != nil {
		fmt.Printf("could not open keys: " + err.Error())
		os.Exit(4)
	}
	
	exitN := 0
	logFormat := os.Args[1]
	switch logFormat {
	case "TraditionalFormat":
		exitN, err = writeLogTraditionalFormat(ledger)
		exitN += 10
	case "PassThrough":
		exitN, err = writeLogPassThrough(ledger)
		exitN += 20
	default:
		err = fmt.Errorf("unsupported format")
		exitN += 30
	}

	if err == nil {
		return // success
	}

	// error
	print(err.Error() + "\n")
	os.Exit(exitN)
}

func writeLogTraditionalFormat(ledger *immledger.ImmLedger) (exitN int, retErr error) {
	buf := make([]byte, 1024)
	logLen, err := os.Stdin.Read(buf)
	if err != nil {
		return 1, fmt.Errorf("read error: %s", err)
	}
	buf = buf[:logLen]

	// get program name
	const timeFmt = "Jan 02 15:04:05"
	hostnameP := len(timeFmt)+1
	if hostnameP > logLen {
		return 2, fmt.Errorf("unexpected log: there is no timestamp in log")
	}
	
	hostProgMsg := buf[hostnameP:]
	strs := strings.Split(string(hostProgMsg), ":")
	strs = strings.Split(strs[0], " ")
	progName := []byte("unknownProg")
	if len(strs) > 1 {
		// unexpected log format
		progName = []byte(strs[1])
	}

	// trim PID
	progTail := len(progName)
	for i, ch := range progName {
		if ch == '[' {
			progTail = i
			break
		}
	}
	progNameShort := progName[:progTail]

	ledger.Write("", string(progNameShort), string(buf))
	return 0, nil // success
}

func writeLogPassThrough(ledger *immledger.ImmLedger) (exitN int, retErr error) {
	if len(os.Args) < 3 {
		return 1, fmt.Errorf("invalid argument")
	}
	progName := os.Args[2]

	var err error
	var logLen int
	buf := make([]byte, 4096)
	for {
		logLen, err = os.Stdin.Read(buf)
		if err != nil {
			break
		}
		buf = buf[:logLen]

		ledger.Write("", progName, string(buf))
	}

	if err != io.EOF {
		return 2, fmt.Errorf("failed to read log: " + err.Error())
	}
	
	return 0, nil // success
}
