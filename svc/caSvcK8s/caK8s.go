package main

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
	caConfHostDir = "conf"
	caDataHostDir = "data"
	caConfDir = "/etc/hyperledger/fabric-ca-server-config"
	caDataDir = "/etc/hyperledger/fabric-ca-server"
)

func startCA(caAdminName, caAdminPass string, subj *pkix.Name, netName string ) error {
	// create a CA for transcation
	keyDir := immutil.ConfBaseDir+ "/"+subj.CommonName+ "/"+caConfHostDir 
	caPrivFile, caCertFile, err := immutil.CreateSelfKeyPair(subj, keyDir)
	if err != nil {
		return fmt.Errorf("failed to create keys for %s transcation: %s", subj.CommonName, err)
	}

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
	hostConfDir := immutil.ConfBaseDir + "/" + subj.CommonName
	startCaCmd := "fabric-ca-server start"
	startCaCmd += " --ca.certfile "+caCert + " --ca.keyfile "+caPrv
	startCaCmd += " -b "+caAdminName+":"+caAdminPass + " -d --cfg.identities.allowremove"
	startCaCmd += " --cfg.affiliations.allowremove"

	deployClient, err := immutil.K8sGetDeploymentClient()
	if err != nil {
		return err
	}
	
	repn := int32(1)
	pathType := corev1.HostPathType(corev1.HostPathDirectoryOrCreate)
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
							Name: "vol1",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: hostConfDir,
									Type: &pathType,
								},
							},
						},
					},
					Hostname: immutil.CAHostname,
					Subdomain: immutil.K8sSubDomain,
					Containers: []corev1.Container{
						{
							Name: immutil.CAHostname,
							Image: immutil.CaImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "vol1", MountPath: caDataDir, SubPath: "data", },
								{ Name: "vol1", MountPath: caConfDir, SubPath: "conf", },
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
			Type: corev1.ServiceTypeLoadBalancer,
			//ExternalIPs: []string{"192.168.120.183"}, // fix me
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
