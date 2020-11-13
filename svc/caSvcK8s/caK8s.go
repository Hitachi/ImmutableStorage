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
	
	"crypto/x509/pkix"
	"fmt"

	"immutil"
)

const (
	caConfDir = "/etc/hyperledger/fabric-ca-server-config"
	caDataDir = "/etc/hyperledger/fabric-ca-server"
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

	org := subj.Organization[0]
	caHostname := subj.CommonName
	caCert := caConfDir + "/" + caCertFile
	caPrv  := caConfDir + "/" + caPrivFile
	caName := caHostname
	caEnv := []corev1.EnvVar{
		{ Name: "FABRIC_CA_HOME", Value: caDataDir, },
		{ Name: "FABRIC_CA_SERVER_CA_NAME", Value: caName, },
		{ Name: "FABRIC_CA_SERVER_TLS_ENABLED", Value: "true", },
		{ Name: "FABRIC_CA_SERVER_TLS_CERTFILE", Value: caCert, },
		{ Name: "FABRIC_CA_SERVER_TLS_KEYFILE", Value: caPrv, },
	}
	startCaCmd := "fabric-ca-server start"
	startCaCmd += " --ca.certfile "+caCert + " --ca.keyfile "+caPrv
	startCaCmd += " -b "+caAdminName+":"+caAdminPass + " -d --cfg.identities.allowremove"
	startCaCmd += " --cfg.affiliations.allowremove"

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
					},
					Hostname: immutil.CAHostname,
					Subdomain: immutil.K8sSubDomain,
					Containers: []corev1.Container{
						{
							Name: immutil.CAHostname,
							Image: pullRegAddr + immutil.CaImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "work-vol", MountPath: caDataDir, SubPath: caHostname+"/data", },
								{ Name: "keys-vol1", MountPath: caConfDir, },
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

func stopCA(subj *pkix.Name) error {
	err := immutil.K8sDeleteService(immutil.CAHostname)
	if err != nil {
		return err
	}

	return immutil.K8sDeleteDeploy(subj.CommonName)
}
