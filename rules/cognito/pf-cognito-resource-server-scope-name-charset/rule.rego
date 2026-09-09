package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-resource-server-scope-name-charset", "ERROR", name,
	sprintf("Properties.Scopes.%d.ScopeName", [s.index]),
	sprintf("scope name '%s' has characters outside the allowed set; the resource server create fails with \"Member must satisfy regular expression pattern: [\\x21\\x23-\\x2E\\x30-\\x5B\\x5D-\\x7E]+\"", [n]),
	"Use a scope name without whitespace, double quotes, slashes or backslashes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolresourceserver.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolResourceServer")
	some s in flatten_list(name, "Properties.Scopes")
	is_object(s.value)
	n := object.get(s.value, "ScopeName", "")
	is_string(n)
	n != ""
	not regex.match(`^[\x21\x23-\x2E\x30-\x5B\x5D-\x7E]+$`, n)
}
