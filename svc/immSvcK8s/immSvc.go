package main

import (
	"fmt"
	"os"
)

func main(){
	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Printf("Usage: immSvc {start|stop} organization_name [immsrv]\n")
		os.Exit(1)
	}

	cmd := os.Args[1]
	org := os.Args[2]

	var	immSrvF string
	if len(os.Args) == 4 {
		immSrvF = os.Args[3]
	}
	onlyImmsrvF := false
	if immSrvF == "immsrv" {
		onlyImmsrvF = true
	}
	err := immSvc(cmd, org, onlyImmsrvF)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}	
}
