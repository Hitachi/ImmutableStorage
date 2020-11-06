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

### Immutable Storage service client
There are the following three type of clients for each application.

1. Web application
You can extend your web application to record immutable and confidential data using WASM module (i.e. imms.wasm)

2. Linux native application
Your Linux native application can add Immutable Storage functions to link a library without writing lots of codes.

3. Syslog client
Syslog client can add Immutable Storage functions to edit a configuration for rsyslog without adding codes.

## Install

### Immutalbe Storage service
#### What you'll need
- An kubernetes enviroment such as microk8s
