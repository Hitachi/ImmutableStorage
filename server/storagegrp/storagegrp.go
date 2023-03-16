/*
Copyright Hitachi, Ltd. 2023 All Rights Reserved.

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

package storagegrp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/asn1"
	"immclient"
)

func GetStorageGrpAttr(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ! ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}) {
			continue
		}
		
		attrs := &immclient.Attributes{}
		err := json.Unmarshal(ext.Value, attrs)
		if err != nil {
			continue
		}
		
		hostname, ok := attrs.Attrs[immclient.StorageGrpAttr]
		if ok {
			return hostname
		}
	}

	return ""
}
