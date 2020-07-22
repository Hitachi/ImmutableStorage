package immutil

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/kubernetes"
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
	"strings"
	"bufio"
)

const (
	DNS_CONF_KEY = "Corefile"
	
	NotReady = "NotReady"
	Ready = "Ready"
	NotExist = "NotExist"
)

func createClientSet() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	tokenStat,err  := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	isInKubeF := err == nil && !tokenStat.IsDir() &&
		os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
		os.Getenv("KUBERNETES_SERVICE_PORT") != ""
	
	if isInKubeF {
		// inside kubernetes
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", os.Getenv("HOME")+"/.kube/config")
	}
		
	//	config, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %s\n", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create a client-set: %s\n", err)
	}
	
	return clientset, nil
}

func K8sGetDeploymentClient() (appsv1.DeploymentInterface, error) {
	clientset, err := createClientSet()
	if err != nil {
		return nil, err
	}

	return clientset.AppsV1().Deployments(corev1.NamespaceDefault), nil
}

func K8sGetPodClient() (clientv1.PodInterface, error) {
	clientset, err := createClientSet()
	if err != nil {
		return nil, err
	}
	return clientset.CoreV1().Pods(corev1.NamespaceDefault), nil
}

func K8sGetServiceClient() (clientv1.ServiceInterface, error) {
	clientset, err := createClientSet()
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
	clientset, err := createClientSet()
	if err != nil {
		return nil, err
	}

	return clientset.CoreV1().ConfigMaps(name), nil
}

func K8sGetSecretsClient() (clientv1.SecretInterface, error) {
	clientset, err := createClientSet()
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
	
	secret, retErr := secretsClient.Get(context.TODO(), secretName, metav1.GetOptions{})
	if retErr != nil {
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
