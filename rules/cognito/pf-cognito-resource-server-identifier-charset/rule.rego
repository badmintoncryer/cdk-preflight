package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-resource-server-identifier-charset", "ERROR", name,
	"Properties.Identifier",
	sprintf("identifier '%s' has characters outside the allowed set; the resource server create fails with \"Member must satisfy regular expression pattern: [\\x21\\x23-\\x5B\\x5D-\\x7E]+\"", [v]),
	"Use an identifier without whitespace (e.g. https://api.example.com)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolresourceserver.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolResourceServer")
	v := resolve(name, "Properties.Identifier")
	is_string(v)
	not input.resources[v]
	v != ""
	not regex.match(`^[\x21\x23-\x5B\x5D-\x7E]+$`, v)
}
