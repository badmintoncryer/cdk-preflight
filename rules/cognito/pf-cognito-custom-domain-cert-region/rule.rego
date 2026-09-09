package cdk_preflight

import rego.v1

# The hosted UI custom domain is fronted by CloudFront, so the certificate
# follows the CloudFront rule regardless of where the pool lives.

violation contains make_diag_full("pf-cognito-custom-domain-cert-region", "ERROR", name,
	"Properties.CustomDomainConfig.CertificateArn",
	sprintf("the certificate is in %v; the domain create fails with \"The specified SSL certificate doesn't exist, isn't in us-east-1 region, isn't valid, or doesn't include a valid certificate chain.\"", [r]),
	"Issue or import the certificate in us-east-1 and reference that ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooldomain.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolDomain")
	arn := resolve(name, "Properties.CustomDomainConfig.CertificateArn")
	r := _pf_coglib_arn_region(arn)
	r != "us-east-1"
}
