# ImmutableStorage

Immutable Storage for storing history, log or ledger.

To detect who recored data and changed data or not, recorded data is signed by recorder private key and stored with certificate to storage. We are also able to know where storage has data since stored data is signed by storage service.
It is important to store your private key to your private storage. You should not store decrypted private key to remote storage. However, you can not create signature before decrypting private key with secret password. Therefore, you should sign data in your LOCAL computer.

Immutable Storage is a tool to store unchangeable data such as history, log, or ledger.

Immutable Storage functions:
- Identity access management
- Remote storage management
- Library for storing immutable data to keep using private key in local computer
- Library for confidential data

## Structure
Immutable Storage consists of Immutable Storage service and client.
![Immutable Storage Structure](./doc/img/ImmsServerClient.svg)

### Immutable Storage service
Immutable Storage service records data on Kubernetes environment.
Only one storage service is no problem for immutable and confidential although you can create more than one storage service to be redundant of data storage.
Storage Group consists of one or more than one Immutable Storage service.

### Immutable Storage client
There are the following three types of client for each application.

1. Web application
You can extend your web application to record immutable and confidential data using WASM module (i.e. imms.wasm)

2. Linux native application
Your Linux native application can add Immutable Storage functions from a library without writing lots of codes.

3. Syslog client
Your syslog client will get Immutable Storage functions without adding codes if you edit a configuration file for rsyslogd.

## Install
## Install Immutable Storage service
### What you'll need
- Kubernetes such as microk8s
- containerd for image registry
- An Internet connection

### 1. Install a container to your registry
Immutable Storage server can be installed to your registry with the following command as root or through sudo.

```sh
ctr i import ImmutableStorage-1.0.0.tar  --base-name imms
ctr i push REGISTRY/imms:1.0.0 imms:1.0.0
```

REGISTRY is your registry. For example, local registry is "localhost:32000" on microk8s. ctr command may be replaced by microk8s.ctr on microk8s.

### 2. Configure resources for Immutable Storage service
To configure resources for Immutable Storage service, you need to edit some lines in the imms-example.yaml file.

If, for example, your registry is localhost:32000, the line defined image is the following:
 ```yaml
  - image: localhost:32000/imms:1.0.0
 ```

You must define an organization name for Immutable Storage service. This organization name will be also used as domain name in hostname.
If you want to set an organization name to example.com, a value in the imms-example.yaml file looks like:
```yaml
    - name: IMMS_ORG
      value: example.com
```

Immutable Storage service needs a containerd socket in order to pull docker images. You need to set this socket path in the imms-example.yaml file. On microk8s, containerd socket path is /var/snap/microk8s/common/run/containerd.sock:
```yaml
 - name: containerd-sock
    hostPath:
      path: /var/snap/microk8s/common/run/containerd.sock
```

### 3. Create resouces for Immutable Storage service
Immutable Storage server resource can be created with the following command as root or through sudo.

```sh
kubectl create -f imms-example.yaml
```

### 4. Create Immutable Storage
#### 4.1. Enroll CA administrator
![Enroll CA admin](./doc/img/enrollAdmin.jpg)


## Legal
### License
Unless otherwise noted, source files are distributed under the Apache License, Version 2.0 found in the LICENSE file.

### Trademarks
Linux and Kubernets are trademarks of The Linux Foundation registered in the United States and/or other countries. All other trademars are the property of their respective owners.
