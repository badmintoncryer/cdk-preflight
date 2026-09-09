package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-web-authn-relying-party-format", "ERROR", name,
	"Properties.WebAuthnRelyingPartyID",
	sprintf("WebAuthnRelyingPartyID '%s' is not a bare domain name; the relying party id takes no scheme, port or path", [v]),
	"Use the domain only (example.com), with no scheme, port or path",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	v := resolve(name, "Properties.WebAuthnRelyingPartyID")
	is_string(v)
	not input.resources[v]
	not regex.match(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`, v)
}
