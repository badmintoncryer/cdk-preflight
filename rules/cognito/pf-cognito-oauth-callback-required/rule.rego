package cdk_preflight

import rego.v1

# Redirect-based flows need somewhere to redirect to. Absence is proven
# against the preprocessed document (see AGENTS.md).
_pf_cogocr_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-cognito-oauth-callback-required", "ERROR", name,
	"Properties.CallbackURLs",
	sprintf("AllowedOAuthFlows has '%s' but CallbackURLs is not set; the client create fails with \"CallbackUrls can not be empty when code flow or implicit flow is selected\"", [f.value]),
	"Add at least one callback URL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	coerce_to_bool(resolve(name, "Properties.AllowedOAuthFlowsUserPoolClient")) == true
	some f in flatten_list(name, "Properties.AllowedOAuthFlows")
	f.value in {"code", "implicit"}
	_pf_cogocr_absent(name, "CallbackURLs")
}
