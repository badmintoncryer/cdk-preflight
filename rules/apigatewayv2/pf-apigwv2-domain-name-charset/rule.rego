package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-domain-name-charset", "ERROR", name,
	"Properties.DomainName",
	sprintf("DomainName '%s' has characters a custom domain name cannot take (upper case letters or underscores)", [d]),
	"Use lower case letters, digits, dots and hyphens only",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-domainname.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::DomainName")
	d := resolve(name, "Properties.DomainName")
	is_string(d)
	not input.resources[d]
	not regex.match(`^[a-z0-9.-]+$`, d)
}
