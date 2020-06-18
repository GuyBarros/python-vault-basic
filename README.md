# python-vault-basic

this is a simple python3 script that: 

* logs into Vault
* creating a static secret
* reading a static secret
* using transit.

## Pre requisites

we are using the HMAC python vault library to facilitate interacting with Vault, for this we will need to install the prerequisites, you can do this with pip by running the following command:

```bash
pip install -r requirements.txt
```

this script also expects vault related to the address, token and namespace. you can set these by running the following command:

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
export VAULT_NAMESPACE=example
```

please note: if not using namespaces,  leave it blank. 

## improvements

I will add different feature branches to this project for different necessities. things like:

* Using different auth methods
* Using dynamic credentials
* integrating with different environments like nomad, k8s
* specific use cases, like Blockchain,Big Data and more
