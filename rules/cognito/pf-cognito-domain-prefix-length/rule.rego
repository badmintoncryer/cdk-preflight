package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-domain-prefix-length", "ERROR", name,
	"Properties.Domain",
	sprintf("domain prefix is %d characters; the domain create fails with \"Member must have length less than or equal to 63\"", [count(d)]),
	"Use a domain prefix of at most 63 characters",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooldomain.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolDomain")
	_pf_coglib_absent(_pf_coglib_g1(name, "CustomDomainConfig"))
	d := resolve(name, "Properties.Domain")
	is_string(d)
	count(d) > 63
}
