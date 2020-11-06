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

package main

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/docker/go-connections/tlsconfig"
	dclient "github.com/docker/docker/client"
	"github.com/docker/docker/api/types"
	
	"fmt"
	"net/http"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/tls"

	"os"
	"context"
	"strings"
	
	"immutil"
)

func initDinD(podSel, org string) (retErr error) {
	serviceName, retErr := createDinDService(podSel)
	if retErr != nil {
		return
	}
	defer immutil.K8sDeleteService(serviceName)
	
	return initDockerClient(org)
}

func createDinDService(podSel string) (serviceName string, retErr error) {
	// create a temporary service for docker-in-docer 
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dind",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": podSel,
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "docker",
					Port: 2376,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 2376,
					},
				},
			},
		},
	}

	serviceClient, retErr := immutil.K8sGetServiceClient()
	if retErr != nil {
		return
	}

	resultSvc, err := serviceClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to crate a temporary service for docker-in-docker: %s", err)
		return
	}
	
	serviceName = resultSvc.GetObjectMeta().GetName()
	return
}

func initDockerClient(org string) (retErr error) {
	// initialize docker client
	tlsConfig := tlsconfig.ClientDefault()

	secretCli, retErr  := immutil.K8sGetSecretsClient()
	if retErr != nil {
		return
	}
	secret, err :=  secretCli.Get(context.TODO(), immutil.DinDHostname + "." + org, metav1.GetOptions{})
	if err != nil || secret.Data == nil {
		retErr = fmt.Errorf("not found key: %s", err)
		return
	}
	
	caCertRaw, ok := secret.Data["server/ca.pem"]
	if !ok {
		retErr = fmt.Errorf("not found server/ca.pem")
		return
	}
	certRaw, ok := secret.Data["server/cert.pem"]
	if !ok {
		retErr = fmt.Errorf("not found server/cert.pem")
		return
	}
	keyRaw, ok := secret.Data["server/key.pem"]
	if !ok {
		retErr = fmt.Errorf("not found server/key.pem")
		return
	}

	caRoots := x509.NewCertPool()
	ok = caRoots.AppendCertsFromPEM(caCertRaw)
	if !ok {
		fmt.Printf("failed to append CA certificate\n")
		os.Exit(4)
	}
	tlsConfig.RootCAs = caRoots

	cert, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		fmt.Printf("failed to parse a key pair: %s\n", err)
		os.Exit(5)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: dclient.CheckRedirect,
	}

	dockerClient, err := dclient.NewClientWithOpts(dclient.WithHost("https://dind."+org+":2376"), dclient.WithHTTPClient(httpClient))
	if err != nil {
		retErr = fmt.Errorf("failed to create docker client: %s", err)
		return
	}

	dImgs, err := dockerClient.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to list docker images: %s", err)
		return
	}

	ccenvLatest := strings.SplitN(immutil.ChainCcenvImg, ":", 2)[0] + ":latest"
	var findImgList = map[string] bool {
		immutil.ChainCcenvImg: false, immutil.ChainBaseOsImg: false, ccenvLatest: false, }

	// find images in docker-in-docker
	for _, img := range dImgs {
		for _, tag := range img.RepoTags {
			_, ok := findImgList[tag]
			if ok {
				findImgList[tag] = true
			}
		}
	}

	var imgName string
	var state bool
	for imgName, state = range findImgList {
		if state != false {
			break
		}
	}
	if findImgList[imgName] == true {
		return // success
	}

	// find images in registry
	registryAddr := ""
	registryAuth := ""
	config, _, err :=  immutil.ReadOrgConfig(org)
	if err == nil && config.Registry != ""{
		registryAddr = config.Registry
		registryAuth = config.RegistryAuth
	} else {
		registryAddr, retErr = immutil.GetLocalRegistryAddr()
		if retErr != nil {
			return
		}
	}

	regCli, err := immutil.NewRegClient("http://" + registryAddr, registryAuth)
	if err != nil {
		retErr = fmt.Errorf("could not connect to registry service: %s", err)
		return
	}

	repos, err := regCli.ListRepositoriesInReg()
	if err != nil {
		retErr = fmt.Errorf("failed to list repositoires: %s", err)
		return
	}

	for _, repo := range repos {
		tags, err := regCli.ListTagsInReg(repo)
		if err != nil {
			continue
		}

		for _, tag := range tags {
			ref := repo + ":" + tag
			state, ok := findImgList[ref]
			if !ok || state == true {
				continue
			}

			// pull and tag image
			_, err = dockerClient.ImagePull(context.Background(), registryAddr+"/"+ref, types.ImagePullOptions{})
			if err != nil {
				retErr = fmt.Errorf("failed to pull %s: %s\n", ref, err)
				return
			}
				
			err = dockerClient.ImageTag(context.Background(), ref, registryAddr+"/"+ref)
			if err != nil {
				retErr = fmt.Errorf("failed to tag %s: %s\n", ref, err)
				return
			}
			findImgList[ref] = true
			
			if ref != immutil.ChainCcenvImg {
				continue
			}
			err = dockerClient.ImageTag(context.Background(), ccenvLatest, registryAddr+"/"+ref)
			findImgList[ccenvLatest] = true
		}
	}

	for imgName, state = range findImgList {
		if state == false {
			retErr = fmt.Errorf("not found %s in the specified registry", imgName)
			return
		}
	}

	return // success
}

func createDinDKeys(org string) (retErr error) {
	// set TLS certificates for the docker-in-docker
	tlsCAPriv, tlsCACertPem, err := immutil.K8sGetKeyPair(immutil.TlsCAHostname+"."+org)
	if err != nil {
		return fmt.Errorf("failed to get a key-pair for CA: " + err.Error())
	}
	tlsCACert, _, err := immutil.ReadCertificate(tlsCACertPem)
	if err != nil {
		return err
	}

	tlsSubj := &pkix.Name{
		Country: tlsCACert.Subject.Country,
		Organization: tlsCACert.Subject.Organization,
		Locality: tlsCACert.Subject.Locality,
		Province: tlsCACert.Subject.Province,
		CommonName: immutil.DinDHostname + "." + org,
	}

	tlsPriv, tlsPub, _, err:= createKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create a key-pair for dockerd: %s", err)
	}

	dnsNames := []string{"docker", "localhost", tlsSubj.CommonName}
	tlsCert, err := signPublicKey(tlsPub, tlsSubj, tlsCAPriv, tlsCACertPem, dnsNames)
	if err != nil {
		return fmt.Errorf("failed to create a certificate for dockerd: %s", err)
	}

	cliPriv, cliPub, _, err := createKeyPair()
	if err != nil {
		return fmt.Errorf("failed to create a key-pair for docker client: %s", err)
	}
	tlsSubj.CommonName = immutil.DinDHostname+"client."+org
	cliCert, err := signPublicKey(cliPub, tlsSubj, tlsCAPriv, tlsCACertPem, nil)
	if err != nil {
		return fmt.Errorf("failed to crate a certificate for docker client: %s", err)
	}

	secretKeys := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: immutil.DinDHostname + "." + org,
		},
		Data: map[string][]byte{
			"ca/cert.pem": tlsCACertPem,
			"server/ca.pem": tlsCACertPem,
			"server/key.pem": tlsPriv,
			"server/cert.pem": tlsCert,
			"client/ca.pem": tlsCACertPem,
			"client/key.pem": cliPriv,
			"client/cert.pem": cliCert,
		},
	}

	secretsCli, err := immutil.K8sGetSecretsClient()
	if err != nil {
		return err
	}

	_, err = secretsCli.Create(context.TODO(), secretKeys, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create a secret for dind keys: %s", err)
	}
	
	return nil	
}
