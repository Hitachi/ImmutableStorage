/*
Copyright Hitachi, Ltd. 2023 All Rights Reserved.

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

package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"context"
	"strings"
	_ "embed"
	"golang.org/x/crypto/bcrypt"
	
	corev1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	
	"immop"
	"immclient"
	"immutil"
	"st2mng"
)

//go:embed st2/config.js
var templ_config_js string
//go:embed st2/syslog.actionrunner.conf
var templ_syslog_actionrunner_conf string
//go:embed st2/st2.user.conf
var templ_st2_user_conf string
//go:embed st2/st2.docker.conf
var templ_st2_docker_conf string
//go:embed st2/st2.conf
var templ_st2_conf string
//go:embed st2/st2-auth-log.conf
var templ_st2_auth_log_conf string
//go:embed st2/init-st2.sh
var templ_init_st2_sh string
//go:embed st2/stanley.yaml
var templ_user_stanley_yaml string
//go:embed st2/st2admin.yaml
var templ_user_st2admin_yaml string
//go:embed st2/role_general_user.yaml
var templ_role_general_user_yaml string

const (
	API_PATH = "/st2do"
)

func (s *server) st2Func(req *immop.ImmstFuncRequest, cert *x509.Certificate) (reply *immop.ImmstFuncReply, retErr error) {
	reply = &immop.ImmstFuncReply{}
	
	switch req.Func {
	case st2mng.FCreateEnv:
		reply.Rsp, retErr = s.st2CreateEnv(req, cert)
	}
	return
}

func checkST2EnvAdminRole(cert *x509.Certificate) error {
	role := immclient.GetCertRole(cert)
	if role != st2mng.ROLE_ST2EnvAdmin {
		return fmt.Errorf("You are not assigned to %s.", st2mng.ROLE_ST2EnvAdmin)
	}
	return nil
}

func (s *server) st2CreateEnv(req *immop.ImmstFuncRequest, cert *x509.Certificate) (reply []byte, retErr error) {
	retErr = checkST2EnvAdminRole(cert)
	if retErr != nil {
		return
	}
	
	createEnvReq := &st2mng.CreateEnvReq{}
	err := json.Unmarshal(req.Req, createEnvReq)
	if err != nil {
		retErr = errors.New("unexpected request: " + err.Error())
		return
	}

	// set a configuration for SSO backend
	sso_backend_kwargs := `{"imms_ca_cert": "/etc/st2/ca.cert",`
	sso_backend_kwargs += `"imms_server_cert": "/etc/st2/immsrv.cert",`
	sso_backend_kwargs += `"imms_redirect_url": "https://`+immutil.HttpdHostname+`.`+s.org+`/st2web/st2login.html",`
	sso_backend_kwargs += `"st2_referer": "https://`+immutil.ST2WebHostname+`.`+s.org+`"}`
	st2_conf := strings.Replace(templ_st2_conf, "SSO_BACKEND_KWARGS", sso_backend_kwargs, 1)

	// get certificate for immsrv
	_, immsrvCertPem, err := immutil.K8sGetKeyPair(immutil.ImmsrvHostname+"."+s.org)
	if err != nil {
		retErr = fmt.Errorf("not found Immutable Storage server: ", err)
		return
	}
	
	// set rsyslog host
	rsyslogSvcName, retErr := s.getRsyslogSvcName(createEnvReq.RsyslogUser)
	if retErr != nil {
		return
	}
	st2_conf = strings.Replace(st2_conf, "host = rsyslog", "host = "+rsyslogSvcName, 1)
	
	configName := "st2" + "." + s.org
	st2ConfigFiles := &map[string]string{
		"config.js": templ_config_js,
		"syslog.actionrunner.conf": templ_syslog_actionrunner_conf,
		"st2.user.conf": templ_st2_user_conf,
		"st2.docker.conf": templ_st2_docker_conf,
		"st2.conf": st2_conf,
		"st2-auth-log.conf": templ_st2_auth_log_conf,
		"stanley.yaml": templ_user_stanley_yaml,
		"st2admin.yaml": templ_user_st2admin_yaml,
		"role_general_user.yaml": templ_role_general_user_yaml,
		"immst-ca": string(s.parentCertPem),
		"immsrv.cert": string(immsrvCertPem),
		"init-st2.sh": templ_init_st2_sh,
	}

	err = immutil.K8sStoreFilesOnConfig(configName, &map[string]string{"config": "st2"}, st2ConfigFiles, nil)
	if err != nil {
		retErr = errors.New("failed to create a ConfigMap for StackStorm: " + err.Error())
		return
	}

	var rollbackFunc []func()
	defer func() {
		if retErr == nil {
			return
		}
		for i := len(rollbackFunc)-1; i >= 0; i-- {
			rollbackFunc[i]()
		}
	}()
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteConfigMap(configName)
	})

	
	sClient, err := immutil.K8sGetSecretsClient()
	if err != nil {
		retErr = err
		return
	}

	passwd := immclient.RandStr(16)
	hashB, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
	if err != nil {
		retErr = errors.New("failed to generage a passowrd: " + err.Error())
		return
	}
	htpasswd := "st2admin:" + string(hashB)

	st2CliConf := `# /root/.st2/config
[credentials]
username = st2admin
password = ` + passwd + `
`
	st2Secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "st2." + s.org,
			Labels: map[string]string{
				"app": "st2",
			},
		},
		StringData: map[string]string{
			"htpasswd": htpasswd,
			"st2-cli.conf": st2CliConf,
		},
	}

	_, err = sClient.Create(context.TODO(), st2Secret, metav1.CreateOptions{})
	if err != nil {
		retErr = errors.New("failed to create a secret for a ST2: " + err.Error())
		return
	}
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteSecret(st2Secret.Name)
	})

	pullRegAddr, err := immutil.GetPullRegistryAddr(s.org)
	if err == nil {
		pullRegAddr += "/"
	}

	baseEnvVal := []corev1.EnvVar{
		{ Name: "ST2_AUTH_URL", Value: "http://st2auth:9100/", },
		{ Name: "ST2_API_URL", Value: "http://st2api:9101/", },
		{ Name: "ST2_STREAM", Value: "http://st2stream:9102/", },
	}
	
	baseConfVol := []corev1.VolumeMount{
		{ Name: "config-files", MountPath: "/etc/st2/st2.conf", SubPath: "st2.conf", ReadOnly: true, },
		{ Name: "config-files", MountPath: "/etc/st2/st2.docker.conf", SubPath: "st2.docker.conf", ReadOnly: true, },
		{ Name: "config-files", MountPath: "/etc/st2/st2.user.conf", SubPath: "st2.user.conf", ReadOnly: true, },
	}

	defaultPackVol := []corev1.VolumeMount{
		{ Name: "st2-default-pack-actions", MountPath: "/opt/stackstorm/packs/default/actions", },
		{ Name: "st2-default-pack-rules", MountPath: "/opt/stackstorm/default/rules", },
		{ Name: "st2-default-pack-sensors", MountPath: "/opt/stackstorm/default/sensors", },		
	}

	rbacVol := []corev1.VolumeMount{
		{ Name: "st2-rbac", MountPath: "/opt/stackstorm/rbac", },
		{ Name: "config-files", MountPath: "/opt/stackstorm/rbac/assignments/st2admin.yaml", SubPath: "st2admin.yaml", ReadOnly: true, },
		{ Name: "config-files", MountPath: "/opt/stackstorm/rbac/assignments/stanley.yaml", SubPath: "stanley.yaml", ReadOnly: true, },
		{ Name: "config-files", MountPath: "/opt/stackstorm/rbac/roles/role_general_user.yaml", SubPath: "role_general_user.yaml", ReadOnly: true, },
	}
	
	repn := int32(1)
	ndots := "1"
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: configName,
			Labels: map[string]string{
				"app": "st2",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &repn,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "st2",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "st2",
					},
				},
				Spec: corev1.PodSpec{
					HostAliases: []corev1.HostAlias{{
						IP: "127.0.0.1",
						Hostnames: []string{"st2api", "st2web", "st2auth", "st2stream", "mongo", "redis", "rabbitmq"},
					},},
					DNSConfig: &corev1.PodDNSConfig{
						Options: []corev1.PodDNSConfigOption{
							{ Name: "ndots", Value: &ndots },
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config-files",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: configName,
									},
								},
							},
						},
						{
							Name: "secret-files",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: st2Secret.Name,
								},
							},
						},
						{ Name: "st2-keys", VolumeSource: corev1.VolumeSource{ EmptyDir: &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-packs-configs", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-packs-dev", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-virtualenvs", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-ssh", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-mongodb", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-rabbitmq", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-redis", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-default-pack-actions", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-default-pack-rules", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-default-pack-sensors", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
						{ Name: "st2-rbac", VolumeSource: corev1.VolumeSource{ EmptyDir:  &corev1.EmptyDirVolumeSource{},},},
					},
					Containers: []corev1.Container{
						{
							Name: "mongo",
							Image: pullRegAddr + immutil.MongoDBImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "st2-mongodb", MountPath: "/data/db", },
							},
						},
						
						{
							Name: "rabbitmq",
							Image: pullRegAddr + immutil.RabbitMQImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "st2-rabbitmq", MountPath: "/var/lib/rabbitmq", },
							},
						},

						{
							Name: "redis",
							Image: pullRegAddr + immutil.RedisImg,
							VolumeMounts: []corev1.VolumeMount{
								{ Name: "st2-redis", MountPath: "/data", },
							},
						},

						{
							Name: "st2client",
							Image: pullRegAddr + immutil.ST2ActionRunnerImg,
							Env: append(baseEnvVal, corev1.EnvVar{ Name: "ST2CLIENT", Value: "1", }),
							VolumeMounts: append(append(append(baseConfVol, defaultPackVol...), rbacVol...),
								corev1.VolumeMount{ Name: "st2-keys", MountPath: "/etc/st2/keys", },
								corev1.VolumeMount{ Name: "st2-packs-configs", MountPath: "/opt/stackstorm/configs", },
								corev1.VolumeMount{ Name: "secret-files", MountPath: "/root/.st2/config", SubPath: "st2-cli.conf", ReadOnly: true, },
								corev1.VolumeMount{ Name: "config-files", MountPath: "/etc/st2/init-st2.sh", SubPath: "init-st2.sh", ReadOnly: true, },
							),
							Command: []string{"/bin/bash", "/etc/st2/init-st2.sh"},
						},

						{
							Name: "st2auth",
							Image: pullRegAddr + immutil.ST2AuthImg,
							ImagePullPolicy: corev1.PullAlways,
							VolumeMounts: append(append(baseConfVol, rbacVol...),
								corev1.VolumeMount{ Name: "secret-files", MountPath: "/etc/st2/htpasswd", SubPath: "htpasswd", ReadOnly: true, },
								corev1.VolumeMount{ Name: "config-files", MountPath: "/etc/st2/st2-auth-log.conf", SubPath: "st2-auth-log.conf", ReadOnly: true, },
								corev1.VolumeMount{ Name: "config-files", MountPath: "/etc/st2/ca.cert", SubPath: "immst-ca", ReadOnly: true, },
								corev1.VolumeMount{ Name: "config-files", MountPath: "/etc/st2/immsrv.cert", SubPath: "immsrv.cert", ReadOnly: true, },
							),
						},
						
						{
							Name: "st2api",
							Image: pullRegAddr + immutil.ST2APIImg,
							Env: baseEnvVal,
							VolumeMounts: append(append(append(baseConfVol, defaultPackVol...), rbacVol...),
								corev1.VolumeMount{ Name: "st2-keys", MountPath: "/etc/st2/keys", },
								corev1.VolumeMount{ Name: "st2-packs-configs", MountPath: "/opt/stackstorm/configs", },
								corev1.VolumeMount{ Name: "st2-packs-dev", MountPath: "/opt/stackstorm/packs.dev", },
							),
						},
						{
							Name: "st2stream",
							Image: pullRegAddr + immutil.ST2StreamImg,
							VolumeMounts: baseConfVol,
						},
						{
							Name: "st2scheduler",
							Image: pullRegAddr + immutil.ST2SchedulerImg,
							VolumeMounts: baseConfVol,
						},
						{
							Name: "st2workflowengine",
							Image: pullRegAddr + immutil.ST2WorkflowEngineImg,
							VolumeMounts: append(baseConfVol,
								corev1.VolumeMount{ Name: "st2-keys", MountPath: "/etc/st2/keys", }),	
						},
						{
							Name: "st2actionrunner",
							Image: pullRegAddr + immutil.ST2ActionRunnerImg,
							VolumeMounts: append(append(baseConfVol, defaultPackVol...),
								corev1.VolumeMount{ Name: "st2-keys", MountPath: "/etc/st2/keys", },
								corev1.VolumeMount{ Name: "st2-packs-configs", MountPath: "/opt/stackstorm/configs", },
								corev1.VolumeMount{ Name: "st2-packs-dev", MountPath: "/opt/stackstorm/packs.dev", },
								corev1.VolumeMount{ Name: "st2-virtualenvs", MountPath: "/opt/stackstorm/virtualenvs",},
								corev1.VolumeMount{ Name: "st2-ssh", MountPath: "/home/stanley/.ssh", },
								corev1.VolumeMount{ Name: "config-files", MountPath: "/etc/st2/syslog.actionrunner.conf", SubPath: "syslog.actionrunner.conf", }),
						},
						{
							Name: "st2garbagecollector",
							Image: pullRegAddr + immutil.ST2GarbageCollectorImg,
							VolumeMounts: baseConfVol,
						},
						{
							Name: "st2notifier",
							Image: pullRegAddr + immutil.ST2NotifierImg,
							VolumeMounts: baseConfVol,
						},
						{
							Name: "st2rulesengine",
							Image: pullRegAddr + immutil.ST2RuleEngineImg,
							VolumeMounts: baseConfVol,
						},
						{
							Name: "st2sensorcontainer",
							Image: pullRegAddr + immutil.ST2SensorContainerImg,
							VolumeMounts: append(append(baseConfVol, defaultPackVol...),
								corev1.VolumeMount{ Name: "st2-packs-configs", MountPath: "/opt/stackstorm/configs", },
								corev1.VolumeMount{ Name: "st2-packs-dev", MountPath: "/opt/stackstorm/packs.dev", },
								corev1.VolumeMount{ Name: "st2-virtualenvs", MountPath: "/opt/stackstorm/virtualenvs",}),
						},
						{
							Name: "st2timerengine",
							Image: pullRegAddr + immutil.ST2TimerEngineImg,
							VolumeMounts: baseConfVol,
						},
						{
							Name: "st2chatops",
							Image: pullRegAddr + immutil.ST2ChatopsImg,
							Env: baseEnvVal,
							VolumeMounts: baseConfVol,
							Command: []string{"/bin/sh", "-c", "sleep 365d",
								// `while true; do curl -s -o /dev/null -m 10 --connect-timeout 5 $ST2_API_URL; if [ $? -ne 0 ]; then echo "st2api not yet available, waiting for retry..."; sleep 5; else echo "st2api is ready, starting hubot...";break;fi;done; bin/hubot --config-check; if [ $? -ne 0 ]; then echo "hubot --config-check failed"; exit 1; fi; bin/hubot`
							},
						},
						{
							Name: "st2web",
							Image: pullRegAddr + immutil.ST2WebImg,
							Env: append(baseEnvVal, corev1.EnvVar{ Name: "ST2WEB_HTTPS", Value: "0", }),
							Command: []string{"/bin/bash", "-c", `if [ ${ST2WEB_HTTPS} = 1 ]; then ST2WEB_TEMPLATE='/etc/nginx/conf.d/st2-https.template'; else ST2WEB_TEMPLATE='/etc/nginx/conf.d/st2-http.template'; fi && sed -Ei 's@(proxy_pass\s+\$\{ST2_AUTH_URL\};)@\1\n    proxy_cookie_path     / "/; SameSite=strict";@' $ST2WEB_TEMPLATE; envsubst '${ST2_AUTH_URL} ${ST2_API_URL} ${ST2_STREAM_URL}' < ${ST2WEB_TEMPLATE} > /etc/nginx/conf.d/st2.conf && exec nginx -g 'daemon off;'`},
							Ports: []corev1.ContainerPort{
								{
									Name: "st2webport",
									Protocol: corev1.ProtocolTCP,
									ContainerPort: 80,
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
			Name: "st2web",
			Labels: map[string]string{
				"svc": "st2",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "st2",
			},
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Name: "st2web",
					Port: 8080,
					TargetPort: intstr.IntOrString{
						Type: intstr.Int,
						IntVal: 80,
					},
				},
			},
		},
	}
	
	retErr = immutil.K8sDeployPodAndService(deployment, service)
	if retErr != nil {
		return
	}
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteService(service.Name)
		immutil.K8sDeleteDeploy(deployment.Name)
	})

	genIngressConf, err := immutil.K8sReadConfig(s.org, immutil.EnvGenIngressConf)
	if err != nil {
		retErr = err
		return
	}
	if genIngressConf == "disable" {
		return
	}

	ingressCli, err := immutil.K8sGetIngressClient()
	if err != nil {
		retErr = errors.New("failed to get an ingress client: " + err.Error())
		return
	}

	tlsSecretName, err := immutil.K8sCreateTLSKeyPairOnSecret(immutil.ST2WebHostname, s.org, true)
	if err != nil {
		retErr = err
		return
	}

	err = immutil.K8sCreateIngressWithTLS(immutil.ST2WebHostname, tlsSecretName, s.org, 8080, "HTTP", 
		[]netv1.IngressTLS{{
			Hosts: []string{tlsSecretName},
			SecretName: tlsSecretName,
		}})
	if err != nil {
		retErr = errors.New("failed to create an ingress: " + err.Error())
		return
	}
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteIngress(immutil.ST2WebHostname)
	})

	pathtype := netv1.PathTypePrefix
	st2immst := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: "st2webimmst",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS",
				"nginx.ingress.kubernetes.io/force-ssl-redirect":`"true"`,
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{{
				Host: tlsSecretName,
				IngressRuleValue: netv1.IngressRuleValue{
					HTTP: &netv1.HTTPIngressRuleValue{
						Paths: []netv1.HTTPIngressPath{{
							Path: "/st2web",
							PathType: &pathtype,
							Backend: netv1.IngressBackend{
								Service: &netv1.IngressServiceBackend{
									Name: immutil.HttpdHostname,
									Port: netv1.ServiceBackendPort{
										Number: 443,
									},},},},},},},},},},}
	
	_, err = ingressCli.Create(context.TODO(), st2immst, metav1.CreateOptions{})
	if err != nil {
		retErr = errors.New("failed to create an ingress: " + err.Error())
		return
	}
	rollbackFunc = append(rollbackFunc, func(){
		immutil.K8sDeleteIngress(st2immst.Name)
	})

	err = immutil.AddProxyPass(immutil.HttpdHostname+"."+s.org, API_PATH, "http://"+service.Name+":8080")
	if err != nil {
		retErr = errors.New("failed to add a proxy: " + err.Error())
		return
	}

	return // success
}

