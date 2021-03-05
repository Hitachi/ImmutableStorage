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

package immsvc

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	
	"crypto/x509/pkix"
	"os"
	"io/ioutil"
	"context"
	"bytes"
	"fmt"
	
	"immutil"
)

const (
	exportDirSuffix = "/export"
	caConfHostDir = "conf"
)

func immSvc(cmd, org string, onlyImmsrvF bool) error {
	config, org, err := immutil.ReadOrgConfig(org)
	if err != nil {
		return err
	}

	immsrvSubj := &pkix.Name{}
	*immsrvSubj = config.Subj
	immsrvSubj.CommonName = immutil.ImmsrvHostname + "." + org

	envoySubj := &pkix.Name{}
	*envoySubj = config.Subj
	envoySubj.CommonName = immutil.EnvoyHostname + "." + org
	switch cmd {
	case "start":
		err = createImmsrvConf(immsrvSubj)
		if err != nil {
			return err
		}
		err = createEnvoyConf(envoySubj)
		if err != nil {
			return err
		}
		
		err = createPod(immsrvSubj, envoySubj, config.ExternalIPs)
		if err != nil {
			return err
		}
		
		err = makeHttpdConf(envoySubj)
		if err != nil {
			return err
		}

		return restartHttpd(org)
	case "stop":
		return stopImmServer(immsrvSubj, envoySubj)

	default:
		return fmt.Errorf("unknown command: %s\n", cmd)
	}

	return nil
}

func createImmsrvConf(subj *pkix.Name) error {
	hostname := subj.CommonName
	immsrvBaseDir := immutil.VolBaseDir+"/"+hostname
	tmplImmSrvConf := immutil.TmplDir+"/immsrv"

	// create a certificate for TLS
	tlsCASecretName := immutil.TlsCAHostname + "." + subj.Organization[0]
	privTLSCA, certTLSCA, err := immutil.K8sGetKeyPair(tlsCASecretName)
	if err != nil {
		return fmt.Errorf("failed to get a key-pair for the TLS CA")
	}
	_, err = immutil.K8sCreateKeyPair(subj, privTLSCA, certTLSCA, nil)
	if err != nil {
		return fmt.Errorf("failed to create keys: %s", err)
	}

	exportDir := immsrvBaseDir + exportDirSuffix
	_, err = os.Stat(exportDir)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) == false {
		return fmt.Errorf("unexpected file state: %s: %s", exportDir, err.Error())
	}

	// copy template
	err = immutil.CopyTemplate(tmplImmSrvConf, exportDir)
	if err != nil {
		return err
	}

	// set DNS
	org := subj.Organization[0]
	return immutil.K8sSetOrgInCoreDNSConf(org)
}

func createEnvoyConf(subj *pkix.Name) error {
	hostname := subj.CommonName

	// create a certificate for TLS
	tlsCASecretName := immutil.TlsCAHostname + "." + subj.Organization[0]
	privTLSCA, certTLSCA, err := immutil.K8sGetKeyPair(tlsCASecretName)
	if err != nil {
		return fmt.Errorf("failed to get a key-pair for the TLS CA")
	}
	_, err = immutil.K8sCreateKeyPair(subj, privTLSCA, certTLSCA, nil)
	if err != nil {
		return fmt.Errorf("failed to create keys: %s", err)
	}
	
	// set immsrv-hostname in envoy.yaml
	_, retErr := immutil.K8sReadEnvoyConfig(hostname)
	if retErr == nil {
		return nil // This configuration already exists
	}
	
	envoyYaml, err := ioutil.ReadFile(immutil.TmplDir + "/envoy/envoy.yaml")
	if err != nil {
		return fmt.Errorf("failed to read a template: %s", err)
	}
	envoyYaml = editEnvoyYaml(envoyYaml, "localhost", immutil.K8sLocalSvc)

	return immutil.K8sWriteEnvoyConfig(hostname, string(envoyYaml))
}

func editEnvoyYaml(srcBuf []byte, immsrvHost, orginMatch string) []byte {
	dstBuf0 := bytes.Replace(srcBuf, []byte("HOSTNAME"), []byte(immsrvHost), 1)
	return bytes.Replace(dstBuf0, []byte("DOMAINNAME"), []byte(orginMatch), 1)
}

func createPod(immsrvSubj, envoySubj *pkix.Name, externalIPs []string) error {
	envoyConfigName := envoySubj.CommonName
	immsrvHostname := immsrvSubj.CommonName

	org := immsrvSubj.Organization[0]
	workVol, err := immutil.K8sGetOrgWorkVol(org)
	if err != nil {
		return err
	}

	pullRegAddr, err := immutil.GetPullRegistryAddr(org)
	if err == nil {
		pullRegAddr += "/"
	}
	
	// start a Pod
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
			Name: immsrvHostname,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:&repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string] string{
					"app": "imm-server",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "imm-server",
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: "immsrv-vol1",
							VolumeSource: *workVol,
						},
						{
							Name: "immsrv-keys-vol",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: immsrvSubj.CommonName,
									Items: []corev1.KeyToPath{
										{ Key: "key", Path: "server.key", Mode: &privMode },
										{ Key: "cert", Path: "server.crt", Mode: &certMode },
									},
								},
							},
						},
						{
							Name: "envoy-configmap-vol",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: envoyConfigName,
									},
								},
							},
						},
						{
							Name: "envoy-keys-vol",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: envoySubj.CommonName,
									Items: []corev1.KeyToPath{
										{ Key: "key", Path: "server.key", Mode: &privMode },
										{ Key: "cert", Path: "server.crt", Mode: &certMode },
									},
								},
							},
						},
					},
					Hostname: "imm-service",
					Subdomain: immutil.K8sSubDomain,
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					Containers: []corev1.Container{
						{
							Name: immutil.ImmsrvHostname,
							Image: pullRegAddr + immutil.ImmSrvImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "immsrv-vol1", MountPath: "/var/lib/immsrv", SubPath: immsrvHostname+exportDirSuffix, },
								{ Name: "immsrv-keys-vol", MountPath: "/var/lib/immsrv/keys", },
							},
							Command: []string{"/var/lib/immsrv/immsrv"},
							Ports: []corev1.ContainerPort{
								{
									Name: "grpc",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 50051,
								},
							},
						},
						{
							Name: immutil.EnvoyHostname,
							Image: pullRegAddr + immutil.EnvoyImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "envoy-configmap-vol", MountPath: "/etc/envoy/conf", },
								{ Name: "envoy-keys-vol", MountPath: "/etc/envoy/keys", },
							},
							//Command: []string{"/usr/local/bin/envoy", "-c", "/etc/envoy/conf/envoy.yaml", "-l", "debug"},
							Command: []string{"/usr/local/bin/envoy", "-c", "/etc/envoy/conf/envoy.yaml"},
							Ports: []corev1.ContainerPort{
								{
									Name: "grpc-web",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 8080,
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
	fmt.Printf("Create deploment %q.\n", result.GetObjectMeta().GetName())

	// create a service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: immutil.EnvoyHostname,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": "imm-server",
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Port: 8080,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 8080,
					},
				},
			},
		},
	}
	if len(externalIPs) > 0 {
		service.Spec.ExternalIPs = externalIPs
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

func removeItemInHttpdConf(src []byte, removeLine, newItem string) ([]byte, bool) {
	itemI := bytes.Index(src, []byte(removeLine))
	if itemI == -1 {
		// not found
		return src, false
	}

	beginI := bytes.LastIndex(src[:itemI], []byte("\n"))
	srcItem := src[beginI+1:]
	endI := bytes.Index(srcItem, []byte("\n"))
	
	if endI == -1 {
		endI = len(srcItem) - 1
	}
	srcItem = srcItem[:endI+1]
	item := make([]byte, len(srcItem))
	copy(item, srcItem)

	removedItem := make([]byte, beginI+1)
	copy(removedItem, src[:beginI+1])
	removedItem = append(removedItem, src[beginI+1+len(item):]...)
		
	if newItem == string(item) {
		// newItem already exists in this source.
		return nil, false
	}

	return removedItem, true // new
}

func makeHttpdConf(envoySubj *pkix.Name) error {
	httpdConfFile := immutil.VolBaseDir+ "/"+immutil.HttpdHostname+"."+envoySubj.Organization[0] + "/conf/httpd.conf"
	envoyHost := immutil.EnvoyHostname+"."+envoySubj.Organization[0]
	
	src, err := ioutil.ReadFile(httpdConfFile)
	if err != nil {
		return fmt.Errorf("could not read " + httpdConfFile)
	}

	// remove an item for envoy host in httpd.conf
	proxyPass := `ProxyPass "/immsrv" "https://` + envoyHost + `:8080"`
	removedItem, modifiedF := removeItemInHttpdConf(src, envoyHost, proxyPass)
	if removedItem == nil {
		return nil
	}
	if modifiedF {
		err = ioutil.WriteFile(httpdConfFile, removedItem, 0644)
		if err != nil {
			return fmt.Errorf("could not write " + httpdConfFile)
		}
	}
	
	// add new item
	out, err := os.OpenFile(httpdConfFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("could not open " + httpdConfFile)
	}
	out.Write([]byte(proxyPass + "\n"))
	out.Close()

	return nil // success
}

func stopImmServer(immsrvSubj, envoySubj *pkix.Name) error {
	err := immutil.K8sDeleteService(immutil.EnvoyHostname)
	if err != nil {
		return err
	}
	
	return immutil.K8sDeleteDeploy(immsrvSubj.CommonName)
}

func restartHttpd(org string) error {
	return immutil.K8sDeletePod("app=httpd", immutil.HttpdHostname+"."+org)
}
