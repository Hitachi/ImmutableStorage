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

package immconf

import (
	"fmt"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
)

type ImmConfidential struct {
	blk *cipher.Block
}

func GetConfidentialTool(myPrivPem, otherPubPem []byte, keyPass string) (conf *ImmConfidential, retErr error) {
	conf = &ImmConfidential{}
	
	privData, _ := pem.Decode(myPrivPem)

	if privData == nil || privData.Type != "PRIVATE KEY" {
		retErr = fmt.Errorf("%s is not private key", privData.Type)
		return
	}

	if x509.IsEncryptedPEMBlock(privData) {
		privAsn1, err := x509.DecryptPEMBlock(privData, []byte(keyPass))
		if err != nil {
			retErr = fmt.Errorf("failed to decrypt the specified key: ", err.Error())
			return
		}

		privData.Bytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privAsn1})
	}

	privKeyBase, err := x509.ParsePKCS8PrivateKey(privData.Bytes)
	if err != nil {
		retErr = fmt.Errorf("Unsupported key format: " + err.Error())
		return
	}
	priv, _ := privKeyBase.(*ecdsa.PrivateKey)

	var pub *ecdsa.PublicKey
	pubData, _ := pem.Decode(otherPubPem)
	if pubData == nil {
		retErr = fmt.Errorf("invalid public key")
		return
	}
	
	switch pubData.Type {
	case  "CERTIFICATE":
		cert, err := x509.ParseCertificate(pubData.Bytes)
		if err != nil {
			retErr = fmt.Errorf("invalid certificate: " + err.Error())
			return
		}

		if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			retErr = fmt.Errorf("This signature algorithm (%s) is not supported", cert.SignatureAlgorithm.String() )
			return
		}

		pub, _ = cert.PublicKey.(*ecdsa.PublicKey)
	case "PUBLIC KEY":
		pubRaw, err := x509.ParsePKIXPublicKey(pubData.Bytes)
		if err != nil {
			retErr = fmt.Errorf("failed to parse public key: " + err.Error())
			return
		}

		var ok bool
		pub, ok = pubRaw.(*ecdsa.PublicKey)
		if !ok {
			retErr = fmt.Errorf("The specified public key format is not supported")
			return
		}
	default:
		retErr = fmt.Errorf("Unexpected type: " + pubData.Type)
		return
	}

	sharedKey, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	block, err := aes.NewCipher(sharedKey.Bytes())
	if err != nil {
		retErr = fmt.Errorf("failed to get cipher block: " + err.Error())
		return
	}

	conf.blk = &block
	return
}

func (conf *ImmConfidential) Encrypt(plain []byte) (cipherText []byte, retErr error) {
	cipherLen := (len(plain) + aes.BlockSize) &^ (aes.BlockSize-1)
	cipherText = make([]byte, aes.BlockSize/*iv*/ + 1/*pad*/ + cipherLen)

	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		retErr = fmt.Errorf("failed to create initialization vector: " + err.Error())
		return
	}

	padLen := cipherLen - len(plain)
	cipherText[aes.BlockSize] = byte(padLen) // pad length
	pad := make([]byte, padLen)
	plain = append(plain, pad...)
	
	mode := cipher.NewCBCEncrypter(*conf.blk, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize+1:], plain)
	return
}

func (conf *ImmConfidential) Decrypt(cipherText []byte) (plainText []byte, retErr error) {
	if len(cipherText) < (aes.BlockSize + 1) {
		retErr = fmt.Errorf("invaild cipher text")
		return
	}
	
	plain := make([]byte, len(cipherText) - aes.BlockSize - 1)
	iv := cipherText[:aes.BlockSize]
	padLen := int(cipherText[aes.BlockSize])
	if len(plain) % aes.BlockSize != 0 {
		retErr = fmt.Errorf("invalid block")
		return
	}
	
	mode := cipher.NewCBCDecrypter(*conf.blk, iv)
	mode.CryptBlocks(plain, cipherText[aes.BlockSize+1:])
	plainText = plain[:len(plain)-padLen]
	return
}
