#!/usr/bin/env python

import hvac
import json
import requests
import os

VAULT_ADDRESS =  os.environ.get('VAULT_ADDR', None)
VAULT_TOKEN =  os.environ.get('VAULT_TOKEN', None)


client = hvac.Client(
    url=VAULT_ADDRESS,
    token=VAULT_TOKEN,
    verify=False,
    )

def getKV():
    

def getPKI():

def transitEncrypt():

def transitDecrypt():

def transitSign():

def transitHMAC():

def transitVerify():
    

#Main gets list of entities and creates groups/policies/kv for each entity
def main():
    entity_keys = listEntities()


if __name__ == '__main__':
    main()
