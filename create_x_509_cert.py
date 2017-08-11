from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join
import logging
import json

CERT_FILE = "sample.crt"
KEY_FILE = "sample.key"
COUNTRY = "US"
STATE = "California"
LOCALITY_NAME = "SAN JOSE"
ORGANIZATION_NAME = "AWS"
ORGANIZATION_UNIT_NAME = "QuickStart"
COMMON_NAME = "quickstart.com"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def lambda_handler(event, context):
    logger.debug('got event {}'.format(event))
    data = json.loads(event['body'])
    
    if data['CN']:
        COMMON_NAME = data['CN']
    
    create_self_signed_cert(".")
    

def create_self_signed_cert(cert_dir):
    
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = COUNTRY
    cert.get_subject().ST = STATE
    cert.get_subject().L = LOCALITY_NAME
    cert.get_subject().O = ORGANIZATION_NAME
    cert.get_subject().OU = ORGANIZATION_UNIT_NAME
    cert.get_subject().CN = COMMON_NAME
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    open(join(cert_dir, CERT_FILE), "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(join(cert_dir, KEY_FILE), "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        