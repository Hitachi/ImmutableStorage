// Copyright Hitachi, Ltd. All Rights Reserved.

package main

import (
	//	"time"
	"fmt"
	"os"
	"strings"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"encoding/hex"
	"encoding/pem"
	"crypto/x509"
	"immclient"
)

type rsyslog2immConf struct {
	UserName  string `yaml:"UserName"`
	KeyPath   string `yaml:"KeyPath"`
	Password  string `yaml:"Password"`
	EnvoyPort string `yaml:"EnvoyPort"`
	StorageGroup string `yaml:"StorageGroup"`
}

const (
	defaultConfigFile = "/etc/rsyslog2imm/config.yaml"
	defaultUserName = "rec2@example.com"
	defaultKeyPath = "/etc/rsyslog2imm"
	defaultPassword = "" // nothing
	defaultPort = "8080"
	defaultStorageGrp = "storage-grp.example.com"
)

func readConf(confFile string) *rsyslog2immConf {
	conf := &rsyslog2immConf{
		UserName:  defaultUserName,
		KeyPath: defaultKeyPath,
		Password: defaultPassword,
		EnvoyPort: defaultPort,
	}

	confData, err := ioutil.ReadFile(confFile)
	if err != nil {
		return conf
	}

	yaml.Unmarshal(confData, conf)
	return conf
}

func (cfg *rsyslog2immConf) openKey() (*immclient.UserID, error) {
	username := (strings.SplitN(cfg.UserName, "@", 2))[0]
	
	priv, err := ioutil.ReadFile(cfg.KeyPath+"/"+username+"_sk")
	if err != nil {
		return nil, fmt.Errorf("OpenKey: " + err.Error())
	}

	privPem, _ := pem.Decode(priv)
	if x509.IsEncryptedPEMBlock(privPem) {
		privAsn1, err := x509.DecryptPEMBlock(privPem, []byte(cfg.Password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt a key: " + err.Error())
		}

		priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1})
	}		

	cert, err := ioutil.ReadFile(cfg.KeyPath+"/"+username+"-cert.pem")
	if err != nil {
		return nil, fmt.Errorf("OpenKey: " + err.Error())
	}

	return &immclient.UserID{Name: username, Priv: priv, Cert: cert}, nil
}

func (cfg *rsyslog2immConf) getUrl() string {
	orgTmp := strings.SplitN(cfg.UserName, "@", 2)
	if len(orgTmp) < 2 {
		return "unknown.local"
	}

	return "immsrv." + orgTmp[1] + ":" + cfg.EnvoyPort
}

func main() {
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

	cfg := readConf(defaultConfigFile)
	print("UserName: " + cfg.UserName + ", KeyPath: " + cfg.KeyPath + ", Password: " + cfg.Password + "\n")
	
	print(hex.Dump(buf))
	id, err := cfg.openKey()
	if err != nil {
		print("could not open keys: " + err.Error() + "\n")
		os.Exit(5)
	}

	id.RecordLedger(cfg.StorageGroup, string(progNameShort), string(buf), cfg.getUrl())
}
