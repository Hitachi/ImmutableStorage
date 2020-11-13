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

package immsvc

import (
	"fmt"
	"os"
)

func Main(args []string){
	argsLen := len(args)
	if argsLen <  2 || argsLen > 4 {
		fmt.Printf("Usage: immSvc {start|stop} [organization_name] [-immsrv]\n")
		os.Exit(1)
	}

	cmd := args[1]

	org := ""
	onlyImmsrvF := false
	for i := 0; (i < 2) && (argsLen > 2 + i); i++ {
		if args[2+i] == "-immsrv" {
			onlyImmsrvF = true
			continue
		}
		if org == "" {	
			org = args[2+i]
		}
	}

	err := immSvc(cmd, org, onlyImmsrvF)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}	
}
