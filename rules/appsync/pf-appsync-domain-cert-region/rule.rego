package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-domain-cert-region", "ERROR", name,
	"Properties.CertificateArn",
	sprintf("the certificate is in region '%s'; the domain name create fails because an AppSync custom domain requires an ACM certificate in us-east-1", [parts[3]]),
	"Request or import the certificate in us-east-1 and use that ARN",
	"https://docs.aws.amazon.com/appsync/latest/devguide/custom-domain-name.html") if {
	some name in resources_of_type("AWS::AppSync::DomainName")
	arn := resolve(name, "Properties.CertificateArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 3
	parts[2] == "acm"
	parts[3] != "us-east-1"
}
