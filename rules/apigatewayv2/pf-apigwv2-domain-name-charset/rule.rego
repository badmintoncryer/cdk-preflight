package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-domain-name-charset", "ERROR", name,
	"Properties.DomainName",
	sprintf("DomainName '%s' has an underscore, which a custom domain name cannot take (\"Domain names cannot contain an underscore character\")", [d]),
	"Use hyphens instead of underscores",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-domainname.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::DomainName")
	d := resolve(name, "Properties.DomainName")
	is_string(d)
	not input.resources[d]
	# measured: an underscore fails. Upper case and a leading "*." (wildcard domains) are not claimed.
	contains(d, "_")
}
