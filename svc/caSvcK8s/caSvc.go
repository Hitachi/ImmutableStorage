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

package casvc

import (
	"immutil"

    "os"
	"fmt"
	"math/rand"
	"time"
)

func Main(args []string){
	argsLen := len(args)
	if (argsLen != 3) && (argsLen != 2) {
		fmt.Printf("Usage: caSvc {start|stop} [organization_name]\n")
		os.Exit(1)
	}

	cmd := args[1]
	org := ""
	if argsLen == 3 {
		org = args[2]
	}
	err := caSvc(cmd, org)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func randStr(num int) string {
	availStr := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567")
	randStr := ""

	for i := 0; i < num; i++ {
		rand.Seed(time.Now().UnixNano())
		randStr += string(availStr[rand.Intn(len(availStr))])
	}

	return randStr
}

func caSvc(cmd, org string) error {
	caAdminName := "admin"
	caAdminPass := randStr(8)
	//	caAdminPass := "adminpw"

	config, org, err := immutil.ReadOrgConfig(org)
	if err != nil {
		return err
	}
	config.Subj.CommonName = immutil.CAHostname+"."+org

	switch cmd {
	case "start":
		err = startCA(caAdminName, caAdminPass, config)
		if err != nil {
			return fmt.Errorf("could not start a CA for %s: %s\n", config.Subj.CommonName, err)
		}
		
	case "stop":
		err = stopCA(&config.Subj)
		if err != nil {
			return fmt.Errorf("could not stop %s: %s\n", config.Subj.CommonName, err)
		}
	case "getPass":
		secret, err := getCAPass(org)
		if err != nil {
			return fmt.Errorf("failed to get initial secret: %s", err)
		}
		fmt.Printf("Initial administrator secret: %s\n", secret)
	default:
		return fmt.Errorf("unknown command: %s\n", cmd)
	}

	return nil
}
