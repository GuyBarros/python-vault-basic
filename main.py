#!/usr/bin/env python
#this is a very basic python code is to serve as an simple reference for future, more robust code
#hvac is the Hashicorp Vault library we are using, you can find the documentation here: https://hvac.readthedocs.io/en/stable/
import hvac
import json
import requests
import os
import pprint
import base64
import time
import timeit
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()

# VAULT_ADDR =  os.environ.get('VAULT_ADDR', 'http://localhost:8200')
# VAULT_TOKEN =  os.environ.get('VAULT_TOKEN', 'root')
# VAULT_NAMESPACE = os.environ.get('VAULT_NAMESPACE', '')

VAULT_ADDR =  os.environ.get('VAULT_ADDR', 'https://do-not-delete-ever.vault.92607e45-319d-44bd-9879-284b72f492b8.aws.hashicorp.cloud:8200')
VAULT_TOKEN =  os.environ.get('VAULT_TOKEN', 's.veV3nve4Cdy3ytDP4Gglxiuk.i0d6T')
VAULT_NAMESPACE = os.environ.get('VAULT_NAMESPACE', 'admin')

client = hvac.Client(
    url=VAULT_ADDR,
    token=VAULT_TOKEN,
    namespace=VAULT_NAMESPACE,
    # verify=False,
    )

def createStaticSecret(mount_point,path,key,value):
    response = client.secrets.kv.v2.create_or_update_secret(
    path=path,
    mount_point=mount_point,
    secret=dict({key:value}),
    )
    if (response):
        pp.pprint("Static Secret created succesfully")
    else:
        pp.pprint(f"Static Secret not created, something went wrong. response : {response}")


def getKV(mount_point,path,key):
    read_response = client.secrets.kv.read_secret_version(path=path,mount_point=mount_point)
    secret = read_response['data']['data'][key]
    pp.pprint(f"Value under path {path}/{key} is {secret}")
def transitCreateKey(name,convergent_encryption,derived,exportable,allow_plaintext_backup,key_type):

    response = client.secrets.transit.create_key(name,convergent_encryption,derived,exportable,allow_plaintext_backup,key_type)
    if (response.status_code == 204):
        pp.pprint("Key created successfully")
    else:
        pp.pprint(f"Key creation failed. response : {response}")

def transitEncrypt(key_name,plaintext):
    # the plaintext parameter is the same as :
    # ba = plaintext.encode("utf-8")
    # encodedBytes = base64.urlsafe_b64encode(ba)
    # encodedStr = str(encodedBytes, "utf-8")
    encrypt_data_response = client.secrets.transit.encrypt_data(
    name=key_name,
    plaintext=str(base64.urlsafe_b64encode(plaintext.encode("utf-8")), "utf-8"),
)
    ciphertext = encrypt_data_response['data']['ciphertext']
    pp.pprint(f"ciphertext: {ciphertext}")
    return ciphertext

def transitDecrypt(key_name,ciphertext):
    decrypt_data_response = client.secrets.transit.decrypt_data(
    name=key_name,
    ciphertext=ciphertext,
    )
    unencodedtext=str(base64.urlsafe_b64decode(decrypt_data_response['data']['plaintext'].encode("utf-8")), "utf-8")
    pp.pprint(f"plaintext: {unencodedtext}")

def transitSign(key_name,plaintext):
    sign_data_response = client.secrets.transit.sign_data(
    name=key_name,
    hash_input=str(base64.urlsafe_b64encode(plaintext.encode("utf-8")), "utf-8"),
    )
    signature = sign_data_response['data']['signature']
    pp.pprint(f"Signed Data: {signature}")
    return signature

def transitVerify(key_name,plaintext,signature):
    verify_signed_data_response = client.secrets.transit.verify_signed_data(
    name=key_name,
    hash_input=str(base64.urlsafe_b64encode(plaintext.encode("utf-8")), "utf-8"),
    signature=signature,
    )
    pp.pprint(f"is a valid signature?: {verify_signed_data_response['data']['valid']}")


def transitHMAC(key_name,hash_input, algorithm):
    generate_hmac_response = client.secrets.transit.generate_hmac(
    name=key_name,
    hash_input=str(base64.urlsafe_b64encode(hash_input.encode("utf-8")), "utf-8"),
    algorithm=algorithm,
    )
    pp.pprint(f"HMAC'd data is: {generate_hmac_response['data']['hmac']}")

def getMetrics():
    url = VAULT_ADDR+ '/v1/sys/metrics?format=prometheus'
    headers = {'X-Vault-Token': VAULT_TOKEN}
    r = requests.get(url, headers=headers)
    pp.pprint(r.text)


#Main just has the calls to the above methods, comment out as needed
def main():

    pp.pprint(f"HVAC Client Initialised?: {client.is_authenticated()}")
   # createStaticSecret("Python","Test","Foo","MamaMia")
   # getKV("Python","Test","Foo")
   # getMetrics()

    transitCreateKey("example",False,False,True,True,"rsa-2048")
    ciphertext = transitEncrypt("example","A very secret Secrets that secrets secretly")
    transitDecrypt("example",ciphertext)
    signature = transitSign("example","A very secure signature")
    transitVerify("example","A very secure signature",signature)
    transitHMAC("example","hashify me","sha2-512")




if __name__ == '__main__':
    main()

