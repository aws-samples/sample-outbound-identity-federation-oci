# Securely Access Oracle Cloud Infrastructure Resources from AWS Workloads Using Outbound Web Identity Federation

This sample demonstrates how an AWS Lambda function can access OCI Object Storage without long-lived credentials, using AWS IAM Outbound Web Identity Federation.

## How it works

1. Lambda requests a JWT from AWS STS (Outbound Identity Federation)
2. Lambda exchanges the JWT for an OCI User Principal Session Token (UPST)
3. Lambda signs the OCI API request with an ephemeral RSA key pair
4. Lambda uploads an object to OCI Object Storage using the signed request

## Prerequisites

- AWS account with Outbound Identity Federation enabled
- OCI tenancy with Identity Domain configured (admin app, runtime app, service user)
- Identity Propagation Trust linking AWS issuer to OCI
- OCI Object Storage bucket with appropriate IAM policy
- Lambda layer with the `cryptography` Python package

## Environment variables

| Variable | Description |
|----------|-------------|
| `OCI_DOMAIN_URL` | OCI Identity Domain URL |
| `OCI_CLIENT_ID` | OCI runtime app client ID |
| `OCI_NAMESPACE` | OCI Object Storage namespace |
| `OCI_BUCKET_NAME` | Target bucket name |
| `OCI_REGION` | OCI region (e.g., `eu-amsterdam-1`) |

The OCI client secret is stored in AWS Secrets Manager as `oci-federation-client-secret`.

## Deployment

1. Create a Lambda layer with the `cryptography` package
2. Create the Lambda function with the code in `lambda_code.py`
3. Set the environment variables listed above
4. Attach an IAM role with permissions for `sts:GetWebIdentityToken` and `secretsmanager:GetSecretValue`
5. Invoke the function

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
