package cdk_preflight

import rego.v1

# Machine-to-machine and user-facing grants are mutually exclusive on one
# client.
_pf_cogcce_flows(name) := {f.value | some f in flatten_list(name, "Properties.AllowedOAuthFlows")}

violation contains make_diag_full("pf-cognito-client-credentials-exclusive", "ERROR", name,
	"Properties.AllowedOAuthFlows",
	sprintf("AllowedOAuthFlows combines client_credentials with '%s'; the client create fails with \"client_credentials flow can not be selected along with code flow or implicit flow.\"", [other]),
	"Split the flows across separate user pool clients",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	flows := _pf_cogcce_flows(name)
	"client_credentials" in flows
	some other in {"code", "implicit"}
	other in flows
}
