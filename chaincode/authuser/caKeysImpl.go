package authuser

import (
	"io/ioutil"
)

type CAKeysImpl struct {
}
func (ca *CAKeysImpl) name() string {
	return ""
}

func (ca *CAKeysImpl) cert() *[]byte {
	fileName := permConfDir + "/ca.pem"
	data, err:= ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}
	return &data
}

func (ca *CAKeysImpl) uCert() *[]byte {
	fileName := permConfDir + "/ucert.pem"
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}
	return &data
}

func (ca *CAKeysImpl) uPriv() *[]byte {
	fileName := permConfDir + "/upriv.pem"
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}
	return &data
}
func NewAuthUser() *CAAuthUser {
	au := new(CAAuthUser)
	au.setKeys(new(CAKeysImpl))
	return au
}
