package main

import (
	"immutil"

	"os"
	"fmt"
)

func main(){
	argsLen := len(os.Args)
	if (argsLen != 3) && (argsLen != 2) {
		fmt.Printf("Usage: httpSvc {start|stop} [organization_name]\n")
		os.Exit(1)
	}

	cmd := os.Args[1]
	org := ""
	if argsLen == 3 {
		org = os.Args[2]
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
