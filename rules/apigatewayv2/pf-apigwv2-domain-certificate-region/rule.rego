package cdk_preflight

import rego.v1

# Lens 3: the certificate must be issued in the region the stack deploys to.
violation contains make_diag_full("pf-apigwv2-domain-certificate-region", "ERROR", name,
	"Properties.DomainNameConfigurations",
	sprintf("DomainNameConfigurations references an ACM certificate in %s but the stack deploys to %s; the domain name create fails with \"Invalid certificate ARN ... Certificate must be in '%s'.\"", [region, data.cdk_preflight.deploy_region, data.cdk_preflight.deploy_region]),
	"Issue or import the certificate in the deployment region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigatewayv2-domainname-domainnameconfiguration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::DomainName")
	some item in flatten_list(name, "Properties.DomainNameConfigurations")
	c := item.value
	is_object(c)
	arn := c.CertificateArn
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "acm"
	region := parts[3]
	region != ""
	region != data.cdk_preflight.deploy_region
}
