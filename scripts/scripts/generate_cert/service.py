# built for AWS Lambda
# author: # Tony Vattathil avattathil@gmail.com
# This program create x509 Private Key,Public Key and Certificate Chain
#

from __future__ import print_function
import json
import requests
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

'''
Generate private_Key Publicr_ Key Certificate_Chain
returns: public_key_certificate, private_key, certificate_chain
'''
def generate_selfsigned_cert(common_name, alternative_names, key_size):
    
    key = rsa.generate_private_key(public_exponent=65537,
                                    key_size=key_size, 
                                    backend=default_backend()
                                    )
    
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    alt_names = x509.SubjectAlternativeName([
        x509.DNSName(alternative_names),
    ])
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(alt_names, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    public = cert.public_bytes(encoding=serialization.Encoding.PEM)
    private = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_certificate = public.decode('utf-8')
    private_key = private.decode('utf-8')
    certificate_chain = ''.join([public_key_certificate,private_key])

    return public_key_certificate, private_key, certificate_chain

'''
Sends Response
input: sendResponse(event, context, responseStatus, responseData)
'''
def sendResponse(event, context, responseStatus, responseData):
    responseData['PRIVATE_KEY'],responseData['PUBLIC_KEY'] = generate_selfsigned_cert(os.environ['common_name'],os.environ['alternative_name'], 1024)
    responseBody = {'Status': responseStatus,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'PhysicalResourceId': context.log_stream_name,
                    'Reason': 'For details see AWS CloudWatch LogStream: ' + context.log_stream_name,
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': responseData}
    try:
        request = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
        if request.status_code != 200:
            print (request.text)
            raise Exception('Error detected in [CFN RESPONSE != 200.')
        return
    except requests.exceptions.RequestException as err:
        print (err)
        raise

def handler(event, context):
    responseStatus = 'SUCCESS'
    responseData = {}
    if event['RequestType'] == 'Delete':
        sendResponse(event, context, responseStatus, responseData)
 
    responseData = {'Success': 'PASSED.'}
    sendResponse(event, context, responseStatus, responseData)
 
if __name__ == '__main__':
    handler('event', 'handler')
