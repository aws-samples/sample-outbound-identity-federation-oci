import boto3
import json
import os
import urllib.request
import urllib.parse
import base64
import hashlib
import email.utils

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def get_secret(secret_id):
    client = boto3.client('secretsmanager')
    return client.get_secret_value(SecretId=secret_id)['SecretString']


def generate_key_pair():
    """Generate an ephemeral RSA key pair. Returns (private_key_pem, public_key_b64)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    public_b64 = "".join(
        line for line in public_pem.splitlines()
        if not line.startswith("-----")
    )
    return private_pem, public_b64


def sign_rsa(private_key_pem, message):
    """Sign a message using RSA-SHA256 with the cryptography library."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None,
    )
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def _safe_urlopen(req):
    """Wrapper around urlopen that rejects non-HTTPS schemes."""
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if not url.startswith("https://"):
        raise ValueError(f"Only https:// URLs are allowed, got: {url}")
    return urllib.request.urlopen(req)  # nosec B310


def exchange_jwt_for_upst(aws_jwt, domain_url, client_id, client_secret, public_key):
    """Exchange AWS JWT for OCI UPST via token exchange endpoint."""
    auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:oci:token-type:oci-upst",
        "subject_token": aws_jwt,
        "subject_token_type": "jwt",
        "public_key": public_key,
    }).encode()

    req = urllib.request.Request(
        f"{domain_url}/oauth2/v1/token",
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {auth}",
        },
    )
    with _safe_urlopen(req) as resp:
        return json.loads(resp.read().decode())["token"]


def lambda_handler(event, context):
    domain_url = os.environ['OCI_DOMAIN_URL']
    client_id = os.environ['OCI_CLIENT_ID']
    namespace = os.environ['OCI_NAMESPACE']
    bucket = os.environ['OCI_BUCKET_NAME']
    region = os.environ['OCI_REGION']

    client_secret = get_secret('oci-federation-client-secret')

    # 1. Generate ephemeral RSA key pair
    private_key_pem, public_key = generate_key_pair()

    # 2. Get AWS JWT via Outbound Identity Federation
    sts = boto3.client('sts')
    jwt_response = sts.get_web_identity_token(
        Audience=['oci-federation'],
        DurationSeconds=300,
        SigningAlgorithm='RS256',
    )
    aws_jwt = jwt_response['WebIdentityToken']

    # 3. Exchange AWS JWT for OCI UPST
    try:
        upst = exchange_jwt_for_upst(
            aws_jwt, domain_url, client_id, client_secret, public_key,
        )
    except urllib.error.HTTPError as e:
        return {"statusCode": e.code, "body": f"Token exchange failed: {e.read().decode()}"}

    # 4. Upload to OCI Object Storage with UPST-signed request
    object_name = "test-from-aws.txt"
    body = b"Hello from AWS Lambda via federation!"

    body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode()
    date = email.utils.formatdate(usegmt=True)
    host = f"objectstorage.{region}.oraclecloud.com"
    path = f"/n/{namespace}/b/{bucket}/o/{object_name}"

    signing_string = (
        f"(request-target): put {path}\n"
        f"date: {date}\n"
        f"host: {host}\n"
        f"content-length: {len(body)}\n"
        f"content-type: text/plain\n"
        f"x-content-sha256: {body_hash}"
    )

    signature = sign_rsa(private_key_pem, signing_string)

    auth_header = (
        f'Signature version="1",'
        f'keyId="ST${upst}",'
        f'algorithm="rsa-sha256",'
        f'headers="(request-target) date host content-length content-type x-content-sha256",'
        f'signature="{signature}"'
    )

    put_req = urllib.request.Request(
        f"https://{host}{path}",
        data=body,
        method="PUT",
        headers={
            "date": date,
            "host": host,
            "content-length": str(len(body)),
            "content-type": "text/plain",
            "x-content-sha256": body_hash,
            "authorization": auth_header,
        },
    )

    try:
        with _safe_urlopen(put_req) as resp:
            return {"statusCode": 200, "body": "Success!"}
    except urllib.error.HTTPError as e:
        return {"statusCode": e.code, "body": f"Upload failed: {e.read().decode()}"}