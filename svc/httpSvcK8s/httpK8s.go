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
	
	"crypto/x509/pkix"
	"fmt"
	"os"
	"bytes"
	"os/exec"

	"immutil"
)

const (
	httpConfCntDir = "/usr/local/apache2/conf"
	httpDataCntDir = "/usr/local/apache2/htdocs"
)

func startHttpd(config *immutil.ImmConfig) error {
	subj := &config.Subj
	hostname := subj.CommonName
	//	caHostname := immutil.CAHostname+strings.TrimPrefix(hostname, immutil.HttpdHostname)

	// create keys for a HTTPD
	secretName, err := immutil.K8sCreateSelfKeyPairWithCAFlag(subj, false)
	if err != nil {
		return fmt.Errorf("failed to create keys for a HTTPD: %s", err)
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
							Command: []string{"/bin/bash", "-c", "while [ ! -f /usr/local/apache2/conf/ready ];do sleep 1; done; httpd-foreground"},
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

	err = immutil.K8sDeployPodAndService(deployment, service)
	if err != nil {
		return err
	}

	var rollbackFunc []func()
	defer func() {
		if err == nil {
			return
		}
		for i := len(rollbackFunc)-1; i >= 0; i-- {
			rollbackFunc[i]()
		}
	}()
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteService(service.Name)
		immutil.K8sDeleteDeploy(deployment.Name)
		immutil.K8sDeleteSecret(secretName)
	})

	podName, err := immutil.K8sWaitPodReadyAndGetPodName("app=httpd", hostname)
	if err != nil {
		return err
	}

	copyDir := func(srcDir, dstDir string) (error) {
		var tarBuf bytes.Buffer
		cmd := exec.Command("/bin/sh", "-c", "tar cf - -C "+srcDir+" .")
		cmd.Stdout = &tarBuf
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to read files: %s", err)
		}

		extractCmd := "tar xf - -C " + dstDir
		err = immutil.K8sExecCmd(podName, immutil.HttpdHostname, []string{"/bin/sh", "-c", extractCmd}, &tarBuf, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to extract files: %s", err)
		}

		return nil
	}

	httpdTmplDir := immutil.TmplDir + "/httpd"
	err = copyDir(httpdTmplDir+"/conf", httpConfCntDir) // copy configuration files
	if err != nil {
		return err
	}

	err = copyDir(httpdTmplDir+"/html", httpDataCntDir) // copy HTML contents
	if err != nil {
		return err
	}

	// edit extra/httpd-ssl.conf
	SSL_CONF := httpConfCntDir+"/extra/httpd-ssl.conf"
	err = immutil.K8sExecCmd(podName, immutil.HttpdHostname, []string{"sed","-i","-e",`s/HOSTNAME/`+hostname+`/`, SSL_CONF}, nil, os.Stdout, nil)
	
	err = immutil.K8sExecCmd(podName, immutil.HttpdHostname, []string{"touch", httpConfCntDir+"/ready"}, nil, os.Stdout, nil)
	if err != nil {
		return fmt.Errorf("failed to write a state file: %s", err)
	}
	
	err = immutil.K8sCreateIngress(service.Name, hostname, org, 443, "HTTPS")
	if err != nil {
		return err
	}
	return  nil // success
}

func stopHttpd(subj *pkix.Name) error {
	err := immutil.K8sDeleteService(immutil.HttpdHostname)
	if err != nil {
		return err
	}
	
	return immutil.K8sDeleteDeploy(subj.CommonName)
}
