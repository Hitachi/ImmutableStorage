# ImmutableDataStorage

Immutable Data Storage for storing history, log or ledger.

To detect who recored data and changed data or not, recorded data is signed by recorder private key and stored with certificate to storage. Recorded  data is also signed by storage services. Therefore we are able to know storage has data.
It is important to store your private key to your private storage. You should not store private key to remote storage without crypt. However you can not create signature before decrypting private key with secret password. Therefore you should sign data in your LOCAL computer.

Immutable Data Storage is a tool to store unchangeable data such as history, log, or ledger.

Immutable Data Storage functions:
- Identity access management
- Remote storage management
- Library for storing immutable data to keep using private key in local computer
- Library for confidential data

## Install

### Storage service

#### What you'll need
- An kubernetes enviroment


config.yaml:
```yaml
country: ["JP"]
locality: ["Tokyo"]
province: ["Shinagawa"]
```

### Client application (library)


