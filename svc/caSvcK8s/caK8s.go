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

package casvc

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
    "context"

	"strings"
	"os/exec"
	"crypto/x509/pkix"
	"fmt"

	"immutil"
)

const (
	caConfDir = "/etc/hyperledger/fabric-ca-server-config"
	caDataDir = "/etc/hyperledger/fabric-ca-server"
	tlsKeyDir = "/etc/hyperledger/tls"
	caCertFile = "ca.crt"
	caPrivFile = "ca.key"
)

func startCA(caAdminName, caAdminPass string, config *immutil.ImmConfig) error {
	subj := &config.Subj
	// create a CA for transcation
	secretName, err := immutil.K8sCreateSelfKeyPair(subj)
	if err != nil {
		return fmt.Errorf("failed to create keys for %s transcation: %s", subj.CommonName, err)
	}

	// create a CA for TLS
	tlsSubj := &pkix.Name{
		Country: subj.Country,
		Organization: subj.Organization,
		Locality: subj.Locality,
		Province: subj.Province,
		CommonName: immutil.TlsCAHostname + "." + subj.Organization[0],
	}
	
	tlsCASecret, err := immutil.K8sCreateSelfKeyPair(tlsSubj)
	if err != nil {
		return fmt.Errorf("failed to create keys for %s CA TLS\n", tlsSubj.CommonName)
	}

	// create a certificate for TLS
	privTLSCA, certTLSCA, _ := immutil.K8sGetKeyPair(tlsCASecret)
	err = immutil.K8sCreateKeyPairWithSecretName(subj, privTLSCA, certTLSCA, nil, secretName+"-tls")
	if err != nil {
		return fmt.Errorf("failed to create a certificate for TLS\n")
	}

	org := subj.Organization[0]
	caHostname := subj.CommonName
	caCert := caConfDir + "/" + caCertFile
	caPrv  := caConfDir + "/" + caPrivFile
	caName := caHostname
	caEnv := []corev1.EnvVar{
		{ Name: "FABRIC_CA_HOME", Value: caDataDir, },
		{ Name: "FABRIC_CA_SERVER_CA_NAME", Value: caName, },
		{ Name: "FABRIC_CA_SERVER_TLS_ENABLED", Value: "true", },
		{ Name: "FABRIC_CA_SERVER_TLS_CERTFILE", Value: tlsKeyDir+"/"+caCertFile, },
		{ Name: "FABRIC_CA_SERVER_TLS_KEYFILE", Value: tlsKeyDir+"/"+caPrivFile, },
	}
	startCaCmd := "fabric-ca-server start"
	startCaCmd += " --ca.certfile "+caCert + " --ca.keyfile "+caPrv
	//startCaCmd += " -b "+caAdminName+":"+caAdminPass + " -d --cfg.identities.allowremove"
	startCaCmd += " -b "+caAdminName+":"+caAdminPass + " --cfg.identities.allowremove"	
	startCaCmd += " --cfg.affiliations.allowremove"
	configFile := caDataDir+"/fabric-ca-server-config.yaml"

	workVol, err := immutil.K8sGetOrgWorkVol(org)
	if err != nil {
		return err
	}

	pullRegAddr, err := immutil.GetPullRegistryAddr(org)
	if err == nil {
		pullRegAddr += "/"
	}
	
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
			Name: caHostname,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:&repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string] string{
					"app": "CA",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "CA",
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{
							Name: "work-vol",
							VolumeSource: *workVol,
						},
						{
							Name: "keys-vol1",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: secretName,
									Items: []corev1.KeyToPath{
										{ Key: "key", Path: caPrivFile, Mode: &privMode },
										{ Key: "cert", Path: caCertFile, Mode: &certMode },
									},
								},
							},
						},
						{
							Name: "keys-tlsca",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: secretName+"-tls",
									Items: []corev1.KeyToPath{
										{ Key: "key", Path: caPrivFile, Mode: &privMode },
										{ Key: "cert", Path: caCertFile, Mode: &certMode },
									},
								},
							},
						},
					},
					Hostname: immutil.CAHostname,
					Subdomain: immutil.K8sSubDomain,
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					Containers: []corev1.Container{
						{
							Name: immutil.CAHostname,
							Image: pullRegAddr + immutil.CaImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "work-vol", MountPath: caDataDir, SubPath: caHostname+"/data", },
								{ Name: "keys-vol1", MountPath: caConfDir, },
								{ Name: "keys-tlsca", MountPath: tlsKeyDir, },
							},
							Env: caEnv,
							Command: []string{"sh", "-c", startCaCmd},
							Ports: []corev1.ContainerPort{
								{
									Name: "https",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 7054,
								},
							},
							StartupProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{"test", "-f", configFile},
									},
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

	// create a service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: immutil.CAHostname,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string] string{
				"app": "CA",
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Port: 7054,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 7054,
					},
				},
			},
		},
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

func stopCA(subj *pkix.Name) error {
	err := immutil.K8sDeleteService(immutil.CAHostname)
	if err != nil {
		return err
	}

	return immutil.K8sDeleteDeploy(subj.CommonName)
}

func getCAPass(org string) (secret string, retErr error) {
	caLabel := "app=CA"
	basePodName := immutil.CAHostname + "." + org

	for {
		podState, ver, err := immutil.K8sGetPodState(caLabel, basePodName)
		if err != nil {
			return "", fmt.Errorf("failed to get a pod state: %s", err)
		}

		if podState == immutil.Ready {
			break
		}
		
		if podState == immutil.NotReady {
			immutil.K8sWaitPodReady(ver, caLabel, basePodName)
			continue
		}

		return "", fmt.Errorf("The CA is in an unexpected state: " + podState)
	}
	
	configFile := immutil.VolBaseDir+"/"+immutil.CAHostname+"."+org+"/data/fabric-ca-server-config.yaml"
	getPassCmd := "grep pass: " + configFile + ` | awk '{print $2;}'`
	cmd := exec.Command("/bin/sh", "-c", getPassCmd)
	cmdStdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create a pipe: %s", err)
	}
	
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("could not get a secret: %s", err)
	}

	passBuf := make([]byte, 256)
	len, err := cmdStdout.Read(passBuf)
	if err != nil {
		return "", fmt.Errorf("failed to read a secret in a configuration file: %s", err)
	}

	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("failed to execute commands: %s", err)
	}

	passBuf = passBuf[:len]
	return strings.TrimSuffix(string(passBuf), "\n"), nil
}
