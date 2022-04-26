# importing the required modules
import timeit
import hvac
import json
import requests
import os
import pprint
import base64
import time
from statistics import median
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()

VAULT_ADDR =  os.environ.get('VAULT_ADDR', '')
VAULT_TOKEN =  os.environ.get('VAULT_TOKEN', '')
VAULT_NAMESPACE = os.environ.get('VAULT_NAMESPACE', '')

client = hvac.Client(
    url=VAULT_ADDR,
    token=VAULT_TOKEN,
    namespace=VAULT_NAMESPACE,
    # verify=False,
    )

repeat_count = 10
execute_count = 1

pp.pprint(f"HVAC Client Initialised?: {client.is_authenticated()}")

####################### Vault Functions ############
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
#   pp.pprint(f"ciphertext: {ciphertext}")
    return ciphertext

def transitDecrypt(key_name,ciphertext):
    decrypt_data_response = client.secrets.transit.decrypt_data(
    name=key_name,
    ciphertext=ciphertext,
    )
    unencodedtext=str(base64.urlsafe_b64decode(decrypt_data_response['data']['plaintext'].encode("utf-8")), "utf-8")
#    pp.pprint(f"plaintext: {unencodedtext}")

def transitSign(key_name,plaintext):
    sign_data_response = client.secrets.transit.sign_data(
    name=key_name,
    hash_input=str(base64.urlsafe_b64encode(plaintext.encode("utf-8")), "utf-8"),
    )
    signature = sign_data_response['data']['signature']
#    pp.pprint(f"Signed Data: {signature}")
    return signature

def transitVerify(key_name,plaintext,signature):
    verify_signed_data_response = client.secrets.transit.verify_signed_data(
    name=key_name,
    hash_input=str(base64.urlsafe_b64encode(plaintext.encode("utf-8")), "utf-8"),
    signature=signature,
    )
#    pp.pprint(f"is a valid signature?: {verify_signed_data_response['data']['valid']}")


def transitHMAC(key_name,hash_input, algorithm):
    generate_hmac_response = client.secrets.transit.generate_hmac(
    name=key_name,
    hash_input=str(base64.urlsafe_b64encode(hash_input.encode("utf-8")), "utf-8"),
    algorithm=algorithm,
    )
 #   pp.pprint(f"HMAC'd data is: {generate_hmac_response['data']['hmac']}")

###################### timetit Functions ###############################
def benchmark_encrypt():
	SETUP_CODE = '''
from __main__ import transitEncrypt
from __main__ import client
from __main__ import repeat_count
from __main__ import execute_count
import hvac
import json
import requests
import os
import pprint
import base64
import time
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()
'''

	TEST_CODE = '''
ciphertext = transitEncrypt("example","A very secret Secrets that secrets secretly")
'''

	# timeit.repeat statement
	times = timeit.repeat(setup = SETUP_CODE,
						stmt = TEST_CODE,
						repeat = repeat_count,
						number = execute_count)

	# printing minimum exec. time
	pp.pprint('Mean Encrypt Time: {} milliseconds'.format(median(times)*1000))
	# pp.pprint('Mean Encrypt Time: {} milliseconds'.format(times))


def benchmark_decrypt():
	SETUP_CODE = '''
from __main__ import transitEncrypt
from __main__ import transitDecrypt
from __main__ import repeat_count
from __main__ import execute_count
from __main__ import client
import hvac
import json
import requests
import os
import pprint
import base64
import time
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()
ciphertext = transitEncrypt("example","A very secret Secrets that secrets secretly")
'''

	TEST_CODE = '''
transitDecrypt("example",ciphertext)
'''

	# timeit.repeat statement
	times = timeit.repeat(setup = SETUP_CODE,
						stmt = TEST_CODE,
						repeat = repeat_count,
						number = execute_count)

	# printing minimum exec. time
	pp.pprint('Mean Decrypt Time: {} milliseconds'.format(median(times)*1000))
	# pp.pprint('Mean Decrypt Time: {} milliseconds'.format(times))

def benchmark_sign():
	SETUP_CODE = '''
from __main__ import transitSign
from __main__ import client
from __main__ import repeat_count
from __main__ import execute_count
import hvac
import json
import requests
import os
import pprint
import base64
import time
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()
'''

	TEST_CODE = '''
signature = transitSign("example","A very secure signature")
'''

	# timeit.repeat statement
	times = timeit.repeat(setup = SETUP_CODE,
						stmt = TEST_CODE,
						repeat = repeat_count,
						number = execute_count)

	# printing minimum exec. time
	pp.pprint('Mean Sign Time: {} milliseconds'.format(median(times)*1000))
	# pp.pprint('Mean Sign Time: {} milliseconds'.format(times))

def benchmark_verify():
	SETUP_CODE = '''
from __main__ import transitSign
from __main__ import transitVerify
from __main__ import repeat_count
from __main__ import execute_count
from __main__ import client
import hvac
import json
import requests
import os
import pprint
import base64
import time
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()
signature = transitSign("example","A very secure signature")
'''

	TEST_CODE = '''
transitVerify("example","A very secure signature",signature)
'''

	# timeit.repeat statement
	times = timeit.repeat(setup = SETUP_CODE,
						stmt = TEST_CODE,
						repeat = repeat_count,
						number = execute_count)

	# printing minimum exec. time
	pp.pprint('Mean Verify Time: {} milliseconds'.format(median(times)*1000))
	# pp.pprint('Mean Verify Time: {} milliseconds'.format(times))

def benchmark_hmac():
	SETUP_CODE = '''
from __main__ import transitHMAC
from __main__ import client
from __main__ import repeat_count
from __main__ import execute_count
import hvac
import json
import requests
import os
import pprint
import base64
import time
from datetime import datetime, timedelta
pp = pprint.PrettyPrinter()
'''

	TEST_CODE = '''
transitHMAC("example","hashify me","sha2-512")
'''

	# timeit.repeat statement
	times = timeit.repeat(setup = SETUP_CODE,
						stmt = TEST_CODE,
						repeat = 5,
						number = execute_count)

	# printing minimum exec. time
	pp.pprint('Mean HMAC Time: {} milliseconds'.format(median(times)*1000))
	# pp.pprint('Mean HMAC Time: {} milliseconds'.format(times))


if __name__ == "__main__":
	benchmark_encrypt()
	benchmark_decrypt()
	benchmark_sign()
	benchmark_verify()
	benchmark_hmac()