package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-custom-domain-fqdn", "ERROR", name,
	"Properties.Domain",
	sprintf("CustomDomainConfig is set but Domain '%s' is a prefix, not an FQDN; the domain create fails with \"Custom domain is not a valid subdomain\"", [d]),
	"Use the full domain (auth.example.com) with CustomDomainConfig, or drop CustomDomainConfig for a prefix domain",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooldomain.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolDomain")
	_pf_coglib_set(_pf_coglib_g1(name, "CustomDomainConfig"))
	d := resolve(name, "Properties.Domain")
	is_string(d)
	not contains(d, ".")
}
