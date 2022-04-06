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

package immutil

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"	
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	//	apiapp "k8s.io/api/apps/v1"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	event "k8s.io/apimachinery/pkg/watch"
	"context"

	"fmt"
	"os"
	"time"
	"archive/tar"
	"bytes"
	"io"
	"log"
	"strings"
	"bufio"
	"crypto/x509/pkix"
	"golang.org/x/term"
)

const (
	DNS_CONF_KEY = "Corefile"
	
	NotReady = "NotReady"
	Ready = "Ready"
	NotExist = "NotExist"

	ERR_NOT_FOUND_SECRET = "not found secret:"
)

func IsInKube() bool {
	tokenStat, err  := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	isInKubeF := err == nil && !tokenStat.IsDir() &&
		os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
		os.Getenv("KUBERNETES_SERVICE_PORT") != ""
	return isInKubeF
}

func createClientSet() (clientset *kubernetes.Clientset, config *rest.Config, retErr error) {
	isInKubeF := IsInKube()
	if isInKubeF {
		// inside kubernetes
		config, retErr = rest.InClusterConfig()
	} else {
		config, retErr = clientcmd.BuildConfigFromFlags("", os.Getenv("HOME")+"/.kube/config")
	}
	
	if retErr != nil {
		retErr = fmt.Errorf("failed to get kubernetes config: %s\n", retErr)
		return
	}
	
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		retErr = fmt.Errorf("failed to create a client-set: %s\n", err)
		return
	}
	
	return // success
}

func K8sGetDeploymentClient() (appsv1.DeploymentInterface, error) {
	clientset, _, err := createClientSet()
	if err != nil {
		return nil, err
	}

	return clientset.AppsV1().Deployments(corev1.NamespaceDefault), nil
}

func K8sGetPodClient() (clientv1.PodInterface, error) {
	clientset, _, err := createClientSet()
	if err != nil {
		return nil, err
	}
	return clientset.CoreV1().Pods(corev1.NamespaceDefault), nil
}

func K8sGetRESTClient() (client rest.Interface, config *rest.Config, retErr error) {
	var clientset *kubernetes.Clientset
	clientset, config, retErr = createClientSet()
	if retErr != nil {
		return
	}

	client = clientset.CoreV1().RESTClient()
	return // success
}

func K8sGetServiceClient() (clientv1.ServiceInterface, error) {
	clientset, _, err := createClientSet()
	if err != nil {
		return nil, err
	}

	return clientset.CoreV1().Services(corev1.NamespaceDefault), nil
}

func K8sDeleteService(serviceName string) error {
	serviceClient, err := K8sGetServiceClient()
	if err != nil {
		return err
	}

	_, err = serviceClient.Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		return nil // skip deleting service
	}
	
	deletePolicy := metav1.DeletePropagationForeground
	err = serviceClient.Delete(context.TODO(), serviceName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,})
	if err != nil {
		return fmt.Errorf("failed to delete a service: %s", err)
	}

	return nil
}

func K8sGetRegistryService() (service *corev1.Service, retErr error) {
	clientset, _, retErr := createClientSet()
	if retErr != nil {
		return
	}

	cli := clientset.CoreV1().Services("container-registry")
	service, err := cli.Get(context.TODO(), "registry", metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf("not found registry service")
		return
	}
	return // success
}

func K8sDeleteDeploy(deploymentName string) error {
	deployClient, err := K8sGetDeploymentClient()
	if err != nil {
		return err
	}

	deletePolicy := metav1.DeletePropagationForeground
	err = deployClient.Delete(context.TODO(), deploymentName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,})
	if err != nil {
		return fmt.Errorf("failed to delete a deployment: %s", err)
	}

	return nil
}

func K8sDeletePod(label, containPodName string) error {
	client, err := K8sGetPodClient()
	if err != nil {
		return err
	}

	list, err := client.List(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		return fmt.Errorf("could not get a list")
	}

	deletePolicy := metav1.DeletePropagationForeground
	for _, pod := range list.Items {
		if ! strings.Contains(pod.Name, containPodName) {
			continue
		}

		err = client.Delete(context.TODO(), pod.Name, metav1.DeleteOptions{
			PropagationPolicy: &deletePolicy,})
		if err != nil {
			return fmt.Errorf("failed to delete a pod: %s", err)
		}
	}

	return nil
}

func K8sGetConfigMapsClient() (clientv1.ConfigMapInterface, error) {
	return K8sGetConfigMapsClientWithNamespace(corev1.NamespaceDefault)
}

func K8sGetConfigMapsClientWithNamespace(name string) (clientv1.ConfigMapInterface, error) {
	clientset, _, err := createClientSet()
	if err != nil {
		return nil, err
	}

	return clientset.CoreV1().ConfigMaps(name), nil
}

func K8sGetSecretsClient() (clientv1.SecretInterface, error) {
	clientset, _, err := createClientSet()
	if err != nil {
		return nil, err
	}

	return clientset.CoreV1().Secrets(corev1.NamespaceDefault), nil
}


func K8sGetCertsFromSecret(secretName string) (CACert, AdminCert, TlsCACert []byte, retErr error) {
	var certs = map[string] *[]byte{
		"msp/cacerts/": &CACert,
		"msp/admincerts/": &AdminCert,
		"msp/tlscacerts/": &TlsCACert,
	}
	retErr = k8sGetKeysFromSecret(secretName, certs)
	return
}

func K8sGetSignKeyFromSecret(secretName string)  (signKey, signCert []byte, retErr error) {
	var keys = map[string] *[]byte{
		"msp/keystore/": &signKey,
		"msp/signcerts/": &signCert,
	}
	retErr = k8sGetKeysFromSecret(secretName, keys)
	return
}

func k8sGetKeysFromSecret(secretName string, keyPEMs map[string] *[]byte) (retErr error) {
	secretsClient, retErr := K8sGetSecretsClient()
	if retErr != nil {
		return
	}
	
	secret, err := secretsClient.Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil || secret.Data == nil {
		retErr = fmt.Errorf("not found key: %s", err)
		return
	}

	tarData, ok := secret.Data["keys.tar"]
	if !ok {
		retErr = fmt.Errorf("not found key on a secret")
		return
	}
	
	tarR := tar.NewReader(bytes.NewReader(tarData))
	readFileN := 0
	keyN := len(keyPEMs)
	for {
		header, err := tarR.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			retErr = fmt.Errorf("failed to read a tar: " + err.Error())
			return
		}
		if header.Typeflag != tar.TypeDir {
			continue
		}

		key, ok := keyPEMs[header.Name]
		if !ok {
			continue
		}
		dirname := header.Name

		header, err = tarR.Next()
		if err == io.EOF || header.Typeflag != tar.TypeReg {
			retErr = fmt.Errorf("could not get a key: " + dirname)
			return
		}
		if ! strings.HasPrefix(header.Name, dirname) {
			retErr = fmt.Errorf("Unexpected data in a secret")
			return
		}

		*key = make([]byte, header.Size)
		len, err := tarR.Read(*key)
		if (int64(len) != header.Size) || (err != io.EOF) {
			retErr = fmt.Errorf("failed to read a file")
			return
		}

		readFileN++
		if readFileN == keyN {
			return // success
		}
	}

	retErr = fmt.Errorf("Unexpected secret")
	return
}

func k8sCheckKeyPair(secretName string) (validKey bool, retErr error) {
	privPem, pubPem, err := K8sGetKeyPair(secretName)	
	if err == nil {
		// check key-pair
		err := CheckKeyPair(privPem, pubPem)
		if err == nil {
			validKey = true
			return // success
		}
	}

	if strings.HasPrefix(err.Error(), ERR_NOT_FOUND_SECRET) {
		validKey = false
		return // not found secret
	}
	
	secretsClient, retErr := K8sGetSecretsClient()
	if retErr != nil {
		return // error
	}

	// This secret already exists.
	// delete a key pair		
	deletePolicy := metav1.DeletePropagationForeground
	retErr = secretsClient.Delete(context.TODO(), secretName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,})
	return
}

func K8sStoreKeyPairOnSecret(privPem, certPem []byte, secretName string) (retErr error) {
	secretsClient, retErr := K8sGetSecretsClient()
	if retErr != nil {
		return // error
	}
	
	secretKeys := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
				Name:secretName,
		},
		Data: map[string][]byte{
			"key": privPem,
			"cert": certPem,
		},	
	}
	
	_, retErr = secretsClient.Create(context.TODO(), secretKeys, metav1.CreateOptions{})
	return
}

func K8sCreateSelfKeyPair(subj *pkix.Name) (secretName string, retErr error) {
	secretName = subj.CommonName

	validKey, retErr := k8sCheckKeyPair(secretName)
	if validKey || retErr != nil {
		return
	}

	privPem, pubPem, _, retErr := GenerateKeyPair(subj, nil)
	if retErr != nil {
		return
	}
	
	retErr = K8sStoreKeyPairOnSecret(privPem, pubPem, secretName)
	return
}

func K8sCreateKeyPairWithSecretName(subj *pkix.Name, caPrivPem, caCertPem []byte, dnsNames []string, secretName string) (retErr error) {
	validKey, retErr := k8sCheckKeyPair(secretName)
	if validKey || retErr != nil {
		return
	}

	privPem, pubPem, retErr := CreateCertificate(subj, caPrivPem, caCertPem, dnsNames)
	if retErr != nil {
		return
	}

	retErr = K8sStoreKeyPairOnSecret(privPem, pubPem, secretName)
	return	
}

func K8sCreateKeyPair(subj *pkix.Name, caPrivPem, caCertPem []byte, dnsNames []string) (secretName string, retErr error) {
	secretName = subj.CommonName
	retErr = K8sCreateKeyPairWithSecretName(subj, caPrivPem, caCertPem, dnsNames, secretName)
	return	
}

func K8sGetKeyPair(secretName string) (privPem, certPem []byte, retErr error) {
	cli, retErr := K8sGetSecretsClient()
	if retErr != nil {
		return
	}

	secret, err := cli.Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf(ERR_NOT_FOUND_SECRET + " %s", err)
		return
	}

	if secret.Data == nil {
		retErr = fmt.Errorf("unexpected secret (name=%s)", secretName)
		return
	}

	certPem, ok := secret.Data["cert"]
	if !ok {
		retErr = fmt.Errorf("unexpected secret data (name=%s)",  secretName)
		return
	}

	privPem, ok = secret.Data["key"]
	if !ok {
		retErr = fmt.Errorf("unexpected secret key data (name=%s)", secretName)
		return
	}

	return
}

func K8sListPod(labelSelector string) (*corev1.PodList, error) {
	podClient, err := K8sGetPodClient()
	if err != nil {
		return nil, err
	}

	return podClient.List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
}

func K8sListConfigMap(labelSelector string) (*corev1.ConfigMapList, error) {
	configMapClient, err := K8sGetConfigMapsClient()
	if err != nil {
		return nil, err
	}

	return configMapClient.List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
}

func K8sSetOrgInCoreDNSConf(org string) error {
	localSvc := strings.TrimPrefix(K8sLocalSvc, ".")
	newConf := "rewrite name suffix " + org + " " + localSvc
	client, err := K8sGetConfigMapsClientWithNamespace("kube-system")
	if err != nil {
		return fmt.Errorf("could not get ConfigMap client: %s", err)
	}

	dnsConf, err := client.Get(context.TODO(), "coredns",  metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("could not get a configuration for coredns: %s", err)
	}
	
	strConf, ok := dnsConf.Data[DNS_CONF_KEY]
	if !ok {
		return fmt.Errorf("There is no corefile in CoreDNS ConfigMap.")
	}

	line := bufio.NewScanner(strings.NewReader(strConf))
	for line.Scan() {
		item := line.Text()
		if strings.Contains(item, "rewrite") && strings.Contains(item, "name") && strings.Contains(item, "suffix") && strings.Contains(item, localSvc) {
			strConf = strings.Replace(strConf, item+"\n", "", 1)
		}
	}

	line = bufio.NewScanner(strings.NewReader(strConf))
	for line.Scan() {
		item := line.Text()
		if ! strings.Contains(item, "reload") {
			continue
		}
		
		indentStr := strings.Split(item, "reload")
		newConf = item + "\n" + indentStr[0] + newConf
		strConf = strings.Replace(strConf, item, newConf, 1)

		dnsConf.Data[DNS_CONF_KEY] = strConf
		_, err = client.Update(context.TODO(), dnsConf, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update ConfigMap: %s", err)
		}

		return nil // success
	}
	
	return fmt.Errorf("could not edit CoreDNS ConfigMap")
}

func K8sWaitPodReady(resourceVersion, label, containPodName string) error {
	client, err := K8sGetPodClient()
	if err != nil {
		return err
	}

	watch, err := client.Watch(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
		ResourceVersion: resourceVersion,
	})
	if err != nil {
		return fmt.Errorf("failed to watch the specified pod: %s\n", err)
	}
	defer watch.Stop()

	timeoutF := false
	for {
		select {
		case got, ok := <- watch.ResultChan():
			if !ok {
				return fmt.Errorf("unexpected state")
			}
			
			//fmt.Printf("get pod event type = %s\n", got.Type)
			if got.Type != event.Modified && got.Type != event.Added {
				return fmt.Errorf("unexpected event type (%s)", got.Type)
			}
			
			pod, ok := got.Object.(*corev1.Pod)
			if !ok {
				return fmt.Errorf("unexpected event\n")
			}
			
			if ! strings.Contains(pod.Name, containPodName) {
				continue
			}
			
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.ContainersReady && cond.Status == corev1.ConditionTrue {
					return nil // success
				}
			}
			
		case <- time.After(30 * time.Second):
			timeoutF = true
		}

		state, _, err := K8sGetPodState(label, containPodName)
		if err != nil {
			return err
		}
		
		if state == Ready {
			return nil // success
		}
		
		if state == NotReady && timeoutF {
			return fmt.Errorf(NotReady)
		}
		
		if state == "Failed" {
			return fmt.Errorf("pod failed")
		}
			
		if timeoutF {
			return fmt.Errorf("NotExist")
		}
	}

	return fmt.Errorf("corrupted code")
}

func K8sWaitPodDeleted(resourceVersion, label, containPodName string) error {
	client, err := K8sGetPodClient()
	if err != nil {
		return err
	}

	watch, err := client.Watch(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
		ResourceVersion: resourceVersion,
	})
		if err != nil {
		return fmt.Errorf("failed to watch the specified pod: %s\n", err)
	}
	defer watch.Stop()

	for {
		select {
		case got, ok := <- watch.ResultChan():
			if !ok {
				return fmt.Errorf("unexpected state")
			}

			if got.Type != event.Deleted { 
				continue
			}

			pod, ok := got.Object.(*corev1.Pod)
			if !ok {
				return fmt.Errorf("unexpected event\n")
			}

			if ! strings.Contains(pod.Name, containPodName) {
				continue
			}

			return nil // done
			
		case <- time.After(45 * time.Second):
			return fmt.Errorf("timeout")
		}
	}

	return fmt.Errorf("corrupted code")
}

func K8sGetPodState(label, containPodName string) (retState, resourceVersion  string, retErr error) {
	client, retErr := K8sGetPodClient()
	if retErr != nil {
		return
	}

	list, err := client.List(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		retErr = fmt.Errorf("could not get a list")
		return
	}

	for _, pod := range list.Items {
		if ! strings.Contains(pod.Name, containPodName) {
			continue
		}

		resourceVersion = pod.ResourceVersion
		
		switch pod.Status.Phase {
		case corev1.PodFailed:
			retState = "Failed"
		case corev1.PodUnknown:
			retState = "Failed"
		case corev1.PodPending:
			retState = NotReady
		case corev1.PodSucceeded:
			retState = "Succeeded"
		case corev1.PodRunning:
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.ContainersReady {
					if cond.Status == corev1.ConditionTrue {
						retState = Ready
						return
					}
				}
			}
			retState = NotReady
		default:
			retState = NotReady
		}
		return
	}

	retState = NotExist
	return
}

func k8sReadOrgConfig(org string) (config *ImmConfig, retErr error) {
	configYaml, retErr := k8sReadConfig(org, "config")
	if retErr != nil {
		return
	}
	
	config, retErr = convertYamlToStruct(org, []byte(configYaml))
	return
}

func k8sReadConfig(configName, key string) (config string, retErr error) {
	cli, retErr := K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}

	configMap, err := cli.Get(context.TODO(), configName, metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to get a ConfigMap: %s", err)
		return
	}

	if configMap.Data == nil {
		retErr = fmt.Errorf("unexpected ConfigMap")
		return
	}
	
	config, ok := configMap.Data[key]
	if !ok {
		retErr = fmt.Errorf("not found data (key=%s)", key)
		return
	}

	return
}

func k8sGenerateOrgConfig(org string) (config *ImmConfig, retErr error) {
	if org == "" {
		org = os.Getenv("IMMS_ORG")
		if org == "" {
			retErr = fmt.Errorf("The specified organaization is empty")
			return
		}
	}
	
	config, err := k8sReadOrgConfig(org)
	if err == nil {
		retErr = err
		return
	}
	
	configItems := map[string] []string{
		"country": { os.Getenv("IMMS_CERT_COUNTRY"), defaultCertCountry },
		"locality": { os.Getenv("MMS_CERT_LOCALITY"), defaultCertLocality },
		"province": { os.Getenv("IMMS_CERT_PROVINCE"), defaultCertProvince },
		"ExternalIPs": { os.Getenv("IMMS_EXTERNAL_IP"), ""},
		"Registry": { os.Getenv("IMMS_REGISTRY"), ""},
	}

	configYaml := ""
	for itemName, item := range configItems {
		configYaml += itemName + ": "
		if item[0] == "" {
			configYaml += item[1] + "\n" // set default string
			continue
		}
		configYaml += item[0] + "\n" // set environment variable
	}

	config, retErr = convertYamlToStruct(org, []byte(configYaml))
	if retErr != nil {
		return
	}

	workVolData, retErr := K8sGetMyVolume()
	if retErr != nil {
		return
	}
	
	retErr = k8sWriteOrgConfig(org, configYaml, workVolData)
	return
}

func k8sWriteOrgConfig(org, configYaml string, workVolData []byte) (retErr error) {
	return	k8sWriteConfig(org, "config", "org", configYaml, workVolData)
}

func k8sWriteConfig(name, fileName, configType, configData string, workVolData []byte) (retErr error) {
	cli, retErr := K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string] string {
				"config": configType,
			},
		},
		Data: map[string]string{
			fileName: configData,
		},
	}

	if workVolData != nil {
		configMap.BinaryData = make(map[string][]byte)
		configMap.BinaryData[workVolume] = workVolData
	}
	
	_, err := cli.Create(context.TODO(), configMap, metav1.CreateOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to create a ConfigMap for %s: %s", name, err.Error())
		return
	}
	
	return
}

func K8sReadEnvoyConfig(name string) (string, error) {
	return k8sReadConfig(name, "envoy.yaml")
}

func K8sWriteEnvoyConfig(name, configYaml string) error {
	return k8sWriteConfig(name, "envoy.yaml", "envoy", configYaml, nil)
}

func K8sGetMyVolume() (volData []byte, retErr error) {
	cli, retErr := K8sGetPodClient()
	if retErr != nil {
		return
	}

	hostname := os.Getenv("HOSTNAME")
	pod, err := cli.Get(context.TODO(), hostname, metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf("not found my pod: %s", err)
		return 
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.Name != workVolume {
			continue
		}

		volData, err = volume.VolumeSource.Marshal()
		if err != nil {
			retErr = fmt.Errorf("unexpected volume: %s", err)
			return
		}
		return // success 
	}

	retErr = fmt.Errorf("not found working volume")
	return
}

func K8sGetOrgWorkVol(org string) (vol *corev1.VolumeSource, retErr error) {
	cli, retErr := K8sGetConfigMapsClient()
	if retErr != nil {
		return
	}

	configMap, err := cli.Get(context.TODO(), org, metav1.GetOptions{})
	if err != nil {
		retErr = fmt.Errorf("failed to get a ConfigMap for volume: %s", err)
		return
	}

	if configMap.BinaryData == nil {
		retErr = fmt.Errorf("unexpected ConfigMap")
		return
	}

	volData, ok := configMap.BinaryData[workVolume]
	if !ok {
		retErr = fmt.Errorf("not found volume")
		return
	}

	vol = &corev1.VolumeSource{}
	err = vol.Unmarshal(volData)
	if err != nil {
		retErr = fmt.Errorf("unexpected volume data: %s", err)
		return
	}

	return // success
}

func K8sExecCmd(podName, containerName string, cmd []string) (retErr error) {
	client, config, err := K8sGetRESTClient()
	if err != nil {
		retErr = err
		return
	}

	req := client.Post().
		Resource("pods").
		Name(podName).
		Namespace(corev1.NamespaceDefault).
		SubResource("exec")
	req.VersionedParams(&corev1.PodExecOptions{
		Container: containerName,
		Command: cmd,
		Stdin: true,
		Stdout: true,
		TTY: true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		retErr = fmt.Errorf("failed to create an executor: %s", err)
		return
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Printf("failed to get current terminal state: %s", err)
	} else {
		defer func() {
			term.Restore(int(os.Stdin.Fd()), oldState)
		}()
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin: os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Tty: true,
	})
	if err != nil {
		retErr = fmt.Errorf("failed to execute a command: %s\n", err)
		return
	}

	return // success
}
