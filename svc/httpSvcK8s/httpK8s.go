package main

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
    "context"
	
	"crypto/x509/pkix"
	"fmt"
	"os"
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
	keyDir := immutil.ConfBaseDir + "/"+subj.CommonName + "/"+confHostSuffix
	privFile, certFile, err := immutil.CreateSelfKeyPair(subj, keyDir)
	if err != nil {
		return fmt.Errorf("failed to create keys for a HTTPD: %s", err)
	}

	// create configuration files
	httpBaseDir := immutil.ConfBaseDir + "/" + hostname
	httpConfDir := httpBaseDir + "/" + confHostSuffix
	tmplConfDir := immutil.TmplDir + "/" + tmplConfHostSuffix
	serverKeyFile := httpConfDir + "/" + "server.key"
	
	_, err = os.Stat(serverKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			// copy template files
			err2 := immutil.CopyTemplate(tmplConfDir, httpBaseDir)
			if err2 != nil {
				return err2
			}

			// copy a private key
			err2 = immutil.CopyFile(httpConfDir+"/"+privFile, httpConfDir+"/server.key", 0400)
			if err2 != nil {
				return fmt.Errorf("could not copy a private key: %s", err2)
			}

			// copy a certificate
			err2 = immutil.CopyFile(httpConfDir+"/"+certFile, httpConfDir+"/server.crt", 0444)
			if err2 != nil {
				os.RemoveAll(serverKeyFile)
				return fmt.Errorf("could not copy certificate: %s", err2)
			}
				
			httpConfFile, err2 := os.OpenFile(httpConfDir + "/httpd.conf", os.O_WRONLY|os.O_APPEND, 0644)
			if err2 != nil {
				os.RemoveAll(serverKeyFile)
				return fmt.Errorf("failed to open a configuration file: %s\n", err2)
			}
			httpConfFile.Write([]byte("ProxyPass \"/ca\" \"https://" + caHostname + ":7054\"\n"))
			httpConfFile.Close()
		} else {
			return fmt.Errorf("unexpected file state: %s", httpConfDir)
		}
	}


	deployClient, err := immutil.K8sGetDeploymentClient()
	if err != nil {
		return err
	}

	repn := int32(1)
	pathType := corev1.HostPathType(corev1.HostPathDirectoryOrCreate)
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
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: httpBaseDir,
									Type: &pathType,
								},
							},
						},
					},
					Hostname: immutil.HttpdHostname,
					Subdomain: immutil.K8sSubDomain,
					Containers: []corev1.Container{
						{
							Name: immutil.HttpdHostname,
							Image: immutil.ImmHttpdImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "vol1", MountPath: httpConfCntDir, SubPath: "conf", },
								{ Name: "vol1", MountPath: httpDataCntDir, SubPath: "html", },
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
			Type: corev1.ServiceTypeLoadBalancer,
			ExternalIPs: config.ExternalIPs,
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

func stopHttpd(subj *pkix.Name) error {
	err := immutil.K8sDeleteService(immutil.HttpdHostname)
	if err != nil {
		return err
	}
	
	return immutil.K8sDeleteDeploy(subj.CommonName)
}
