package main

import (
	"fmt"
	"os"
)

func main(){
	argsLen := len(os.Args)
	if argsLen <  2 || argsLen > 4 {
		fmt.Printf("Usage: immSvc {start|stop} [organization_name] [-immsrv]\n")
		os.Exit(1)
	}

	cmd := os.Args[1]

	org := ""
	onlyImmsrvF := false
	for i := 0; (i < 2) && (argsLen > 2 + i); i++ {
		if os.Args[2+i] == "-immsrv" {
			onlyImmsrvF = true
			continue
		}
		if org == "" {	
			org = os.Args[2+i]
		}
	}

	err := immSvc(cmd, org, onlyImmsrvF)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}	
}
