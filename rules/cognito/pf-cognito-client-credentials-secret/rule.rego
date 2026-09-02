package cdk_preflight

import rego.v1

# Machine-to-machine auth is secret-based. GenerateSecret defaults to
# false, so both the literal false and the absent key leave the client
# secretless. Absence is proven against the preprocessed document (see
# AGENTS.md).
_pf_cogccs_no_secret(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "GenerateSecret", "__pf_absent") == "__pf_absent"
}

_pf_cogccs_no_secret(name) if coerce_to_bool(resolve(name, "Properties.GenerateSecret")) == false

violation contains make_diag_full("pf-cognito-client-credentials-secret", "ERROR", name,
	"Properties.GenerateSecret",
	"client_credentials flow on a client without a secret; the client create fails with \"client_credentials flow can not be selected if client does not have a client secret.\"",
	"Set GenerateSecret: true on this client",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	some f in flatten_list(name, "Properties.AllowedOAuthFlows")
	f.value == "client_credentials"
	_pf_cogccs_no_secret(name)
}
