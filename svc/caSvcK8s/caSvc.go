package main

import (
	"immutil"

    "os"
	"fmt"
	"math/rand"
	"time"
)

func main(){
	argsLen := len(os.Args)
	if (argsLen != 3) && (argsLen != 2) {
		fmt.Printf("Usage: caSvc {start|stop} [organization_name]\n")
		os.Exit(1)
	}

	cmd := os.Args[1]
	org := ""
	if argsLen == 3 {
		org = os.Args[2]
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
	default:
		return fmt.Errorf("unknown command: %s\n", cmd)
	}

	return nil
}
