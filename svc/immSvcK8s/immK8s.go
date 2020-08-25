package main

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
	config, err := immutil.ReadConf(org)
	if err != nil {
		return err
	}

	immsrvSubj := &pkix.Name{}
	*immsrvSubj = config.Subj
	immsrvSubj.CommonName = immutil.ImmsrvHostname + "." + config.Subj.Organization[0]

	envoySubj := &pkix.Name{}
	*envoySubj = config.Subj
	envoySubj.CommonName = immutil.EnvoyHostname + "." + config.Subj.Organization[0]
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
	immsrvBaseDir := immutil.ConfBaseDir+"/"+hostname
	tmplImmSrvConf := immutil.TmplDir+"/immsrv"
	exportDir := immsrvBaseDir + exportDirSuffix

	err := createConf(subj, tmplImmSrvConf, immsrvBaseDir)
	if err != nil {
		return err
	}

	// copy a CA certificate
	org := subj.Organization[0]
	caHost := immutil.CAHostname+"."+org
	caCertFile := immutil.ConfBaseDir + "/"+caHost + "/"+caConfHostDir +"/"+caHost+"-cert.pem"
	dstCaCertFile := exportDir + "/ca.crt"
	_, err = os.Stat(dstCaCertFile)
	if err != nil {
		if os.IsNotExist(err) == false {
			return fmt.Errorf("unexpected file state: %s: %s", dstCaCertFile, err.Error())
		}
		err = immutil.CopyFile(caCertFile, dstCaCertFile, 0444)
		if err != nil {
			return err
		}
	}

	return immutil.K8sSetOrgInCoreDNSConf(org)
}

func createEnvoyConf(subj *pkix.Name) error {
	hostname := subj.CommonName
	dstConfDir := immutil.ConfBaseDir + "/" + hostname

	err := createConf(subj, immutil.TmplDir+"/envoy", dstConfDir)
	if err != nil {
		return err
	}

	// set immsrv-hostname in envoy.yaml
	envoyYaml := dstConfDir + exportDirSuffix + "/envoy.yaml"
	err = editEnvoyYaml(envoyYaml, "localhost", immutil.K8sLocalSvc)
	if err != nil {
		return err
	}

	return nil
}

func createConf(subj *pkix.Name, tmplConfDir, dstConfDir string) error {
	exportDir := dstConfDir + exportDirSuffix

	// create keys
	privFile, certFile, err := immutil.CreateSelfKeyPair(subj, dstConfDir)
	if err != nil {
		return fmt.Errorf("failed to create keys\n")
	}

	_, err = os.Stat(exportDir)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) == false {
		return fmt.Errorf("unexpected file state: %s: %s", exportDir, err.Error())
	}

	// create configuration files
	// copy template
	err = immutil.CopyTemplate(tmplConfDir, exportDir)
	if err != nil {
		return err
	}

	// copy private key
	err = immutil.CopyFile(dstConfDir+"/"+privFile, exportDir+"/server.key", 0400)
	if err != nil {
		os.RemoveAll(exportDir)
		return fmt.Errorf("could not copy a private key: %s", err)
	}

	// copy certificate
	err = immutil.CopyFile(dstConfDir+"/"+certFile, exportDir+"/server.crt", 0444)
	if err != nil {
		os.RemoveAll(exportDir)
		return fmt.Errorf("could not copy a certificate: %s", err)
	}

	return nil
}

func editEnvoyYaml(envoyYaml, immsrvHost, orginMatch string) error {
	srcBuf, err := ioutil.ReadFile(envoyYaml)
	if err != nil {
		return err
	}

	dstBuf0 := bytes.Replace(srcBuf, []byte("HOSTNAME"), []byte(immsrvHost), 1)
	dstBuf  := bytes.Replace(dstBuf0, []byte("DOMAINNAME"), []byte(orginMatch), 1)

	err = ioutil.WriteFile(envoyYaml, dstBuf, 0644)
	if err != nil {
		return err
	}

	return nil
}

func createPod(immsrvSubj, envoySubj *pkix.Name, externalIPs []string) error {
	immsrvExport := immutil.ConfBaseDir+"/"+immsrvSubj.CommonName+exportDirSuffix
	envoyExport := immutil.ConfBaseDir+"/"+envoySubj.CommonName+exportDirSuffix
	
	// start a Pod
	deployClient, err := immutil.K8sGetDeploymentClient()
	if err != nil {
		return err
	}

	repn := int32(1)
	pathType := corev1.HostPathType(corev1.HostPathDirectoryOrCreate)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: immsrvSubj.CommonName,
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
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: immsrvExport,
									Type: &pathType,
								},
							},
						},
						{
							Name: "envoy-vol1",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: envoyExport,
									Type: &pathType,
								},
							},
						},
					},
					Hostname: "imm-service",
					Subdomain: immutil.K8sSubDomain,
					Containers: []corev1.Container{
						{
							Name: immutil.ImmsrvHostname,
							Image: immutil.ImmSrvImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "immsrv-vol1", MountPath: "/var/lib/immsrv", },
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
							Image: immutil.EnvoyImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "envoy-vol1", MountPath: "/etc/envoy", },
							},
							Command: []string{"/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml", "-l", "debug"},
							//Command: []string{"/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml"},
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
			Name: immutil.ImmsrvHostname,
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
			Type: corev1.ServiceTypeLoadBalancer,
			ExternalIPs: externalIPs,
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

func removeItemInHttpdConf(src []byte, hostname, newItem string) ([]byte, bool) {
	itemI := bytes.Index(src, []byte(hostname))
	if itemI == -1 {
		// not found
		return src, false
	}

	endI := bytes.Index(src[itemI:], []byte("\n"))
	beginI := bytes.LastIndex(src[:itemI], []byte("\n"))

	item := make([]byte, len(src[beginI+1:]))
	item = append([]byte(nil), src[beginI+1:]...)

	removedItem := make([]byte, beginI+1)
	removedItem = append([]byte(nil), src[:beginI+1]...)

	if endI != -1 {
		item = item[:itemI+endI-beginI-1]
		removedItem = append(removedItem, src[itemI+endI+1:]...)
	}

	if newItem != string(item) {
		// newItem has already exits in this source.
		return nil, false
	}

	return removedItem, true // new
}

func makeHttpdConf(envoySubj *pkix.Name) error {
	httpdConfFile := immutil.ConfBaseDir+ "/"+immutil.HttpdHostname+"."+envoySubj.Organization[0] + "/conf/httpd.conf"
	envoyHost := immutil.ImmsrvHostname+"."+envoySubj.Organization[0]
	
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
	err := immutil.K8sDeleteService(immutil.ImmsrvHostname)
	if err != nil {
		return err
	}
	
	return immutil.K8sDeleteDeploy(immsrvSubj.CommonName)
}

func restartHttpd(org string) error {
	return immutil.K8sDeletePod("app=httpd", immutil.HttpdHostname+"."+org)
}
