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

package httpsvc

import (
	"immutil"

	"os"
	"fmt"
)

func Main(args []string){
	argsLen := len(args)
	if (argsLen != 3) && (argsLen != 2) {
		fmt.Printf("Usage: httpSvc {start|stop} [organization_name]\n")
		os.Exit(1)
	}

	cmd := args[1]
	org := ""
	if argsLen == 3 {
		org = args[2]
	}
	err := httpSvc(cmd, org)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func httpSvc(cmd, org string) error {
	config, org, err := immutil.ReadOrgConfig(org)
	if err != nil {
		return err
	}
	config.Subj.CommonName = immutil.HttpdHostname+"."+org
	
	switch cmd {
	case "start":
		err = startHttpd(config)
		if err != nil {
			return err
		}
	case "stop":
		stopHttpd(&config.Subj)

	default:
		return fmt.Errorf("unknown command: %s\n", cmd)
	}

	return nil
}
