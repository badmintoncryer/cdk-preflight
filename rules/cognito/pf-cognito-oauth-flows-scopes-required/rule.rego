package cdk_preflight

import rego.v1

# Both directions deploy-verified. Absence is proven against the
# preprocessed document (see AGENTS.md).
_pf_cogofs_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

_pf_cogofs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html"

_pf_cogofs_msg := "the client create fails with \"AllowedOAuthFlows and AllowedOAuthScopes are required if user pool client is allowed to use OAuth flows.\""

violation contains make_diag_full("pf-cognito-oauth-flows-scopes-required", "ERROR", name,
	"Properties.AllowedOAuthFlows",
	sprintf("AllowedOAuthFlowsUserPoolClient is true but AllowedOAuthFlows is not set; %s", [_pf_cogofs_msg]),
	"Set AllowedOAuthFlows, or drop AllowedOAuthFlowsUserPoolClient",
	_pf_cogofs_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	coerce_to_bool(resolve(name, "Properties.AllowedOAuthFlowsUserPoolClient")) == true
	_pf_cogofs_absent(name, "AllowedOAuthFlows")
}

violation contains make_diag_full("pf-cognito-oauth-flows-scopes-required", "ERROR", name,
	"Properties.AllowedOAuthScopes",
	sprintf("AllowedOAuthFlowsUserPoolClient is true but AllowedOAuthScopes is not set; %s", [_pf_cogofs_msg]),
	"Set AllowedOAuthScopes, or drop AllowedOAuthFlowsUserPoolClient",
	_pf_cogofs_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	coerce_to_bool(resolve(name, "Properties.AllowedOAuthFlowsUserPoolClient")) == true
	_pf_cogofs_absent(name, "AllowedOAuthScopes")
}
