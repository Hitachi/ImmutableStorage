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

package immledger

import (
	"immclient"
	"strings"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"fmt"
	"encoding/pem"
	"crypto/x509"
	"github.com/hyperledger/fabric/protos/common"
)

const (
	defaultConfigFile = "./immconfig.yaml"
	ERR_PASS_INCORRECT = "failed to decrypt a key:"
)

type ImmCfgInf interface {
	SetDefaultUrl(org string)
	GetKeyParam() (keyPath, userName, password string)
	GetEndpoint() (storageGroup, url string)
}

func OpenKeyFromCfg(cfg ImmCfgInf) (userID *immclient.UserID, retErr error) {
	path, userAndOrg, password := cfg.GetKeyParam()

	userAndOrgStr := strings.SplitN(userAndOrg, "@", 2)
	username := userAndOrgStr[0]
	org := ""
	if len(userAndOrgStr) >= 2 {
		org = userAndOrgStr[1]
	}
	
	priv, err := ioutil.ReadFile(path+"/"+username+"_sk")
	if err != nil {
		retErr = fmt.Errorf("OpenKey: failed to read a private key: " + err.Error())
		return
	}

	privPem, _ := pem.Decode(priv)
	if x509.IsEncryptedPEMBlock(privPem) {
		privAsn1, err := x509.DecryptPEMBlock(privPem, []byte(password))
		if err != nil {
			retErr = fmt.Errorf(ERR_PASS_INCORRECT + " " + err.Error())
			return
		}

		priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1})
	}		

	cert, err := ioutil.ReadFile(path+"/"+username+"-cert.pem")
	if err != nil {
		retErr = fmt.Errorf("OpenKey: failed to read a certificate: " + err.Error())
		return
	}

	userID = &immclient.UserID{Name: username, Priv: priv, Cert: cert}
	
	issuerOrg, err := userID.GetIssuerOrg()
	if err != nil {
		retErr = fmt.Errorf("OpenKey: invalid key: " + err.Error())
		return
	}
	
	if (org != "") && (org != issuerOrg) {
		retErr = fmt.Errorf("OpenKey: The specified organization was unexpected. (expected: %s)", issuerOrg)
		return
	}
	cfg.SetDefaultUrl(issuerOrg)
	
	return
}

type ImmCfg struct {
	KeyPath   string `yaml:"KeyPath"`
	UserName  string `yaml:"UserName"`
	Password string `yaml:"Password"`
	StorageGroup string `yaml:"StorageGroup"`
	url string `yaml:"URL"`
}

func readCfgFile(cfgFile string) (cfg *ImmCfg) {
	cfg = &ImmCfg{}

	if cfgFile == "" {
		cfgFile = defaultConfigFile
	}
	
	cfgData, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		return
	}

	yaml.Unmarshal(cfgData, cfg)
	return
}

func (cfg *ImmCfg) SetDefaultUrl(org string) {
	cfg.url = "envoy." + org + ":8080"
}

func (cfg *ImmCfg) GetKeyParam() (keyPath, userName, password string) {
	return cfg.KeyPath, cfg.UserName, cfg.Password
}

func (cfg *ImmCfg) GetEndpoint() (storageGroup, url string) {
	return cfg.StorageGroup, cfg.url
}

func (cfg *ImmCfg) readCfgWithDefault(defaultCfg *ImmCfg) {
	if cfg.KeyPath == "" {
		cfg.KeyPath = defaultCfg.KeyPath
	}
	if cfg.UserName == "" {
		cfg.UserName = defaultCfg.UserName
	}
	if cfg.StorageGroup == "" {
		cfg.StorageGroup = defaultCfg.StorageGroup
	}
	
	return
}

type ImmLedger struct {
	cfg ImmCfgInf
	id *immclient.UserID
}

func OpenKeyWithDefault(cfgFile string, defaultCfg *ImmCfg) (st *ImmLedger, retErr error) {
	st = &ImmLedger{}
	cfg := readCfgFile(cfgFile)
	cfg.readCfgWithDefault(defaultCfg)
	st.id, retErr = OpenKeyFromCfg(cfg)
	st.cfg = cfg
	return
}

func OpenKeyWithCfgFile(userAndOrg, path, password, cfgFile string) (st *ImmLedger, retErr error) {
	st = &ImmLedger{}
	
	cfg := readCfgFile(cfgFile)
	if path != "" {
		cfg.KeyPath = path
	}
	if userAndOrg != "" {
		cfg.UserName = userAndOrg
	}
	if password != "" {
		cfg.Password = password
	}
	
	st.id, retErr = OpenKeyFromCfg(cfg)
	st.cfg = cfg
	return
}

func OpenKey(userAndOrg, path, password string) (st *ImmLedger, retErr error) {
	return OpenKeyWithCfgFile(userAndOrg, path, password, "")
}

func (st *ImmLedger) getEndpoint(storageGrp string) (retGroup, retUrl string) {
	retGroup, retUrl = st.cfg.GetEndpoint()
	if storageGrp != "" {
		retGroup = storageGrp
	}

	if ! strings.Contains(retGroup, ".") {
		org, _ := st.id.GetIssuerOrg()
		retGroup += "." + org
	}

	return
}

func (st *ImmLedger) Write(storageGroup, logName, msgLog string) error {
	stGrp, url := st.getEndpoint(storageGroup)
	return st.id.RecordLedger(stGrp, logName, msgLog, url)
}

func (st *ImmLedger) GetTxID(storageGroup, logName string) (txIDs []string, retErr error) {
	stGrp, url := st.getEndpoint(storageGroup)
	history, retErr := st.id.ReadLedger(stGrp, logName, url)
	if retErr != nil {
		return
	}

	txIDs = make([]string, len(*history))
	for i, item := range *history {
		txIDs[i] = item.TxId
	}
	return // success
}

func (st *ImmLedger) GetBlockByTxID(storageGroup, txID string) (block *common.Block, retErr error) {
	stGrp, url := st.getEndpoint(storageGroup)	
	block, retErr = st.id.QueryBlockByTxID(stGrp, txID, url)
	return
}
