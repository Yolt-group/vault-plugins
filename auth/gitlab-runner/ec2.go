package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/vault/builtin/credential/aws/pkcs7"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/pkg/errors"
)

// This certificate is used to verify the PKCS#7 signature of the instance
// identity document. As per AWS documentation, this public key is valid for
// US East (N. Virginia), US West (Oregon), US West (N. California), EU
// (Ireland), EU (Frankfurt), Asia Pacific (Tokyo), Asia Pacific (Seoul), Asia
// Pacific (Singapore), Asia Pacific (Sydney), and South America (Sao Paulo).
//
// It's also the same certificate, but for some reason listed separately, for
// GovCloud (US)
const genericAWSPublicCertificatePKCS7 = `-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----
`

// identityDocument represents the items of interest from the EC2 instance
// identity document
type identityDocument struct {
	Tags        map[string]interface{} `json:"tags,omitempty"`
	InstanceID  string                 `json:"instanceId,omitempty"`
	AmiID       string                 `json:"imageId,omitempty"`
	AccountID   string                 `json:"accountId,omitempty"`
	Region      string                 `json:"region,omitempty"`
	PendingTime string                 `json:"pendingTime,omitempty"`
}

func (b *backend) newEC2Client(ctx context.Context, cfg *configStorageEntry, region string) (*ec2.EC2, error) {

	awsConfig := &aws.Config{
		Region:     aws.String(region),
		HTTPClient: cleanhttp.DefaultClient(),
		MaxRetries: aws.Int(cfg.AWSMaxRetries),
	}

	if cfg.AWSSTSRole != "" {
		sess, err := session.NewSession(awsConfig)
		if err != nil {
			return nil, err
		}

		assumedCreds := stscreds.NewCredentials(sess, cfg.AWSSTSRole)
		// Test that we actually have permissions to assume the role
		if _, err := assumedCreds.Get(); err != nil {
			return nil, errors.Wrap(err, "failed to assume role")
		}
		awsConfig.Credentials = assumedCreds
	} else {
		credsConfig := &awsutil.CredentialsConfig{
			Region:     region,
			HTTPClient: cleanhttp.DefaultClient(),
		}

		creds, err := credsConfig.GenerateCredentialChain()
		if err != nil {
			return nil, err
		}
		if creds == nil {
			return nil, errors.New("could not compile valid credential providers from static config, environment, shared, or instance metadata")
		}

		awsConfig.Credentials = creds
	}

	clt := ec2.New(session.New(awsConfig))
	if clt == nil {
		return nil, errors.New("could not obtain ec2 client")
	}

	return clt, nil
}

func (b *backend) getEC2Instance(ctx context.Context, cfg *configStorageEntry, idDoc *identityDocument) (*ec2.Instance, error) {

	ec2Client, err := b.newEC2Client(ctx, cfg, idDoc.Region)
	if err != nil {
		return nil, err
	}

	status, err := ec2Client.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(idDoc.InstanceID),
		},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "error fetching description for instance ID %q", idDoc.InstanceID)
	}
	if status == nil {
		return nil, errors.New("nil output from describe instances")
	}
	if len(status.Reservations) == 0 {
		return nil, errors.New("no reservations found in instance description")
	}
	if len(status.Reservations[0].Instances) == 0 {
		return nil, errors.New("no instance details found in reservations")
	}
	if *status.Reservations[0].Instances[0].InstanceId != idDoc.InstanceID {
		return nil, errors.New("expected instance ID not matching the instance ID in the instance description")
	}
	if status.Reservations[0].Instances[0].State == nil {
		return nil, errors.New("instance state in instance description is nil")
	}

	return status.Reservations[0].Instances[0], nil
}

// Decodes the PEM encoded certiticate and parses it into a x509 cert
func decodePEMAndParseCertificate(pemCert string) (*x509.Certificate, error) {
	// Decode the PEM block and error out if a block is not detected in the first attempt
	decodedCert, rest := pem.Decode([]byte(pemCert))
	if len(rest) != 0 {
		return nil, errors.New("invalid certificate; should be one PEM block only")
	}

	// Check if the certificate can be parsed
	cert, err := x509.ParseCertificate(decodedCert.Bytes)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("invalid certificate; failed to parse certificate")
	}
	return cert, nil
}

func parseIdentityDocument(pkcs7B64 string) (*identityDocument, error) {
	// Insert the header and footer for the signature to be able to pem decode it
	pkcs7B64 = fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", pkcs7B64)

	// Decode the PEM encoded signature
	pkcs7BER, pkcs7Rest := pem.Decode([]byte(pkcs7B64))
	if len(pkcs7Rest) != 0 {
		return nil, fmt.Errorf("failed to decode the PEM encoded PKCS#7 signature")
	}

	// Parse the signature from asn1 format into a struct
	pkcs7Data, err := pkcs7.Parse(pkcs7BER.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse the BER encoded PKCS#7 signature")
	}

	// Append the generic certificate provided in the AWS EC2 instance metadata documentation
	decodedCert, err := decodePEMAndParseCertificate(genericAWSPublicCertificatePKCS7)
	if err != nil {
		return nil, err
	}

	// Before calling Verify() on the PKCS#7 struct, set the certificates to be used
	// to verify the contents in the signer information.
	pkcs7Data.Certificates = [](*x509.Certificate){decodedCert}

	// Verify extracts the authenticated attributes in the PKCS#7 signature, and verifies
	// the authenticity of the content using 'dsa.PublicKey' embedded in the public certificate.
	if pkcs7Data.Verify() != nil {
		return nil, fmt.Errorf("failed to verify the signature")
	}

	// Check if the signature has content inside of it
	if len(pkcs7Data.Content) == 0 {
		return nil, fmt.Errorf("instance identity document could not be found in the signature")
	}

	var identityDoc identityDocument
	if err := jsonutil.DecodeJSON(pkcs7Data.Content, &identityDoc); err != nil {
		return nil, err
	}

	return &identityDoc, nil
}
