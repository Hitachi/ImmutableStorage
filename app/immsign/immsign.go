/*
Copyright Hitachi, Ltd. 2021 All Rights Reserved.

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

package immsign

import (
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/pem"
	"encoding/asn1"
	"math/big"
	"errors"
	"google.golang.org/protobuf/proto"
	"fabric/protos/msp"
)

type ECDSASignature struct {
	R, S *big.Int
}

func GetRecorderCertificate(creator []byte) (cert *x509.Certificate, retErr error) {
	id := &msp.SerializedIdentity{}
	err := proto.Unmarshal(creator, id)
	if err != nil {
		retErr = errors.New("invalid creator: " + err.Error())
		return
	}

	certData, _ := pem.Decode(id.IdBytes)
	cert, err = x509.ParseCertificate(certData.Bytes)
	if err != nil {
		retErr = errors.New("invalid certificate: " + err.Error())
		return
	}

	return
}

func VerifySignatureCreator(creator, signature, msg []byte) (cert *x509.Certificate, retErr error) {
	cert, retErr = GetRecorderCertificate(creator)
	if retErr != nil {
		return
	}

	retErr = VerifySignatureCert(cert, signature, msg)
	return
}

func VerifySignatureCert(cert *x509.Certificate, signature, msg []byte) (retErr error) {
	sign := &ECDSASignature{}
	asn1.Unmarshal(signature, sign)
	digest := sha256.Sum256(msg)
	ok := ecdsa.Verify(cert.PublicKey.(*ecdsa.PublicKey), digest[:], sign.R, sign.S)
	if !ok {
		retErr = errors.New("verification failure")
		return
	}
	
	return // valid signature
}
