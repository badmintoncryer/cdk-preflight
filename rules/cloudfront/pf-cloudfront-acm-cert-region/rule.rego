package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudfront-acm-cert-region", "ERROR", name,
	"Properties.DistributionConfig.ViewerCertificate.AcmCertificateArn",
	sprintf("CloudFront requires the ACM certificate to be in us-east-1, but the certificate is in %s", [region]),
	"Issue or import the certificate in us-east-1 (e.g. a dedicated us-east-1 stack) and reference that ARN",
	"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html#https-requirements-certificate-issuer") if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	arn := resolve(name, "Properties.DistributionConfig.ViewerCertificate.AcmCertificateArn")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "acm"
	region := parts[3]
	region != ""
	region != "us-east-1"
}
