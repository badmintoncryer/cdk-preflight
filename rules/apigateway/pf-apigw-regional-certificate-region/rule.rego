package cdk_preflight

import rego.v1

# Lens 3: the certificate for a REGIONAL domain must be issued in the region the
# stack deploys to, which only the enforce plugin knows.
_pf_apgrcr_regional(name) if {
	some t in flatten_list(name, "Properties.EndpointConfiguration.Types")
	t.value == "REGIONAL"
}

violation contains make_diag_full("pf-apigw-regional-certificate-region", "ERROR", name,
	"Properties.RegionalCertificateArn",
	sprintf("RegionalCertificateArn points at an ACM certificate in %s but the stack deploys to %s; the domain name create fails with \"Invalid certificate ARN: ... Certificate must be in '%s'.\"", [region, data.cdk_preflight.deploy_region, data.cdk_preflight.deploy_region]),
	"Issue or import the certificate in the deployment region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-domainname.html") if {
	some name in resources_of_type("AWS::ApiGateway::DomainName")
	_pf_apgrcr_regional(name)
	arn := resolve(name, "Properties.RegionalCertificateArn")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "acm"
	region := parts[3]
	region != ""
	region != data.cdk_preflight.deploy_region
}
