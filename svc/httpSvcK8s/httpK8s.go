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

package httpsvc

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
    "context"
	
	"crypto/x509/pkix"
	"fmt"
	"os"
	"io/ioutil"
	"bytes"
	"strings"

	"immutil"
)

const (
	confHostSuffix = "conf"
	tmplConfHostSuffix = "httpd"
	httpConfCntDir = "/usr/local/apache2/conf"
	httpDataCntDir = "/usr/local/apache2/htdocs"
)

func startHttpd(config *immutil.ImmConfig) error {
	subj := &config.Subj
	hostname := subj.CommonName
	caHostname := immutil.CAHostname+strings.TrimPrefix(hostname, immutil.HttpdHostname)

	// create keys for a HTTPD
	secretName, err := immutil.K8sCreateSelfKeyPair(subj)
	if err != nil {
		return fmt.Errorf("failed to create keys for a HTTPD: %s", err)
	}

	// create configuration files
	httpBaseDir := immutil.VolBaseDir + "/" + hostname
	httpConfDir := httpBaseDir + "/" + confHostSuffix
	tmplConfDir := immutil.TmplDir + "/" + tmplConfHostSuffix
	_, err = os.Stat(httpConfDir)
	if err != nil {
		if os.IsNotExist(err) {
			// copy template files
			err2 := immutil.CopyTemplate(tmplConfDir, httpBaseDir)
			if err2 != nil {
				return err2
			}

			// edit httpd.conf
			httpConfFile, err2 := os.OpenFile(httpConfDir + "/httpd.conf", os.O_WRONLY|os.O_APPEND, 0644)
			if err2 != nil {
				return fmt.Errorf("failed to open a configuration file: %s", err2)
			}
			httpConfFile.Write([]byte("ProxyPass \"/ca\" \"https://" + caHostname + ":7054\"\n"))
			httpConfFile.Close()

			// edit extra/httpd-ssl.conf
			sslConfFile := httpConfDir + "/extra/httpd-ssl.conf"
			httpSslConf, err2 := ioutil.ReadFile(sslConfFile)
			if err2 != nil {
				return fmt.Errorf("failed to read httpd-ssl.conf: %s", err2)
			}

			httpSslConf = bytes.Replace(httpSslConf, []byte("HOSTNAME"), []byte(hostname), 1)
			err2 = ioutil.WriteFile(sslConfFile, httpSslConf, 0644)
			if err2 != nil {
				return fmt.Errorf("failed to edit httpd-ssl.conf: %s", err2)
			}
		} else {
			return fmt.Errorf("unexpected file state: %s", httpConfDir)
		}
	}

	org := subj.Organization[0]
	workVol, err := immutil.K8sGetOrgWorkVol(org)
	if err != nil {
		return err
	}

	pullRegAddr, err := immutil.GetPullRegistryAddr(org)
	if err == nil {
		pullRegAddr += "/"
	}
	
	// deploy a pod and a service
	deployClient, err := immutil.K8sGetDeploymentClient()
	if err != nil {
		return err
	}

	repn := int32(1)
	privMode := int32(0400)
	certMode := int32(0444)
	ndots := "1"
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: hostname,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:&repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string] string{
					"app": "httpd",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "httpd",
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: "vol1",
							VolumeSource: *workVol,
						},
						{
							Name: "keys-vol1",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: secretName,
									Items: []corev1.KeyToPath{
										{ Key: "key", Path: "server.key", Mode: &privMode },
										{ Key: "cert", Path: "server.crt", Mode: &certMode },
									},
								},
							},
						},
					},
					Hostname: immutil.HttpdHostname,
					Subdomain: immutil.K8sSubDomain,
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					Containers: []corev1.Container{
						{
							Name: immutil.HttpdHostname,
							Image: pullRegAddr + immutil.ImmHttpdImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "vol1", MountPath: httpConfCntDir, SubPath: hostname+"/conf", },
								{ Name: "vol1", MountPath: httpDataCntDir, SubPath: hostname+"/html", },
								{ Name: "keys-vol1", MountPath: httpConfCntDir+"/keys", },
							},
							Ports: []corev1.ContainerPort{
								{
									Name: "https",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 443,
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := deployClient.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("Could not create a container in a pod: %s\n", err)
	}

	fmt.Printf("Create deployment %q.\n", result.GetObjectMeta().GetName())

	//create a service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: immutil.HttpdHostname,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": "httpd",
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Port:443,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 443,
					},
				},
			},
		},
	}
	if len(config.ExternalIPs) > 0 {
		service.Spec.ExternalIPs = config.ExternalIPs
	}else{
		service.Spec.Type = corev1.ServiceTypeLoadBalancer
	}
	
	serviceClient, err := immutil.K8sGetServiceClient()
	if err != nil {
		return err
	}
	resultSvc, err := serviceClient.Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	fmt.Printf("Create service %q.\n", resultSvc.GetObjectMeta().GetName())
	
	return nil
}

func stopHttpd(subj *pkix.Name) error {
	err := immutil.K8sDeleteService(immutil.HttpdHostname)
	if err != nil {
		return err
	}
	
	return immutil.K8sDeleteDeploy(subj.CommonName)
}
