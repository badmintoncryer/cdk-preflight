package cdk_preflight

import rego.v1

# The AuthParameters block must match AuthorizationType, and an OAuth
# authorization endpoint must be HTTPS. Measured 2026-09-07,
# events:CreateConnection, us-east-1: BASIC with ApiKeyAuthParameters gives
# "Parameter BasicAuthParameters is not valid. Reason: Missing required
# field(s)", and an http:// endpoint gives "Parameter AuthorizationEndpoint
# is not valid".
_pf_evconn_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-authparameters.html"

_pf_evconn_block := {
	"BASIC": "BasicAuthParameters",
	"API_KEY": "ApiKeyAuthParameters",
	"OAUTH_CLIENT_CREDENTIALS": "OAuthParameters",
}

violation contains make_diag_full("pf-events-connection-auth-parameters", "ERROR", name,
	sprintf("Properties.AuthParameters.%s", [block]),
	sprintf("AuthorizationType is %s but AuthParameters has no %s; CreateConnection fails with \"Parameter %s is not valid. Reason: Missing required field(s)\"", [t, block, block]),
	sprintf("Add AuthParameters.%s", [block]),
	_pf_evconn_url) if {
	some name in resources_of_type("AWS::Events::Connection")
	t := resolve(name, "Properties.AuthorizationType")
	block := _pf_evconn_block[t]
	ap := input.resources[name].properties.AuthParameters
	is_object(ap)
	object.get(ap, block, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-events-connection-auth-parameters", "ERROR", name,
	"Properties.AuthParameters.OAuthParameters.AuthorizationEndpoint",
	sprintf("'%s' is not HTTPS; CreateConnection fails with \"Parameter AuthorizationEndpoint is not valid\"", [ep]),
	"Use an https:// authorization endpoint",
	_pf_evconn_url) if {
	some name in resources_of_type("AWS::Events::Connection")
	ep := resolve(name, "Properties.AuthParameters.OAuthParameters.AuthorizationEndpoint")
	is_string(ep)
	not startswith(ep, "https://")
}
