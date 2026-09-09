package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-domain-prefix-format", "ERROR", name,
	"Properties.Domain",
	sprintf("domain prefix '%s' has characters outside [a-z0-9-]; the domain create fails with \"The domain name contains an invalid character. Domain names can only contain lower-case letters, numbers, and hyphens.\"", [d]),
	"Use lower-case letters, digits and hyphens only, starting and ending with a letter or digit",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooldomain.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolDomain")
	_pf_coglib_absent(_pf_coglib_g1(name, "CustomDomainConfig"))
	d := resolve(name, "Properties.Domain")
	is_string(d)
	not input.resources[d]
	not regex.match(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`, d)
}
