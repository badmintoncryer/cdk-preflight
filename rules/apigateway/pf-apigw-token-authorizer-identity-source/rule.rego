package cdk_preflight

import rego.v1

# TOKEN authorizers read the token from the header named by IdentitySource,
# so the create call rejects its absence. REQUEST authorizers are out of
# scope: they need it only with caching enabled (unmeasured). Absence is
# proven against the preprocessed document (see AGENTS.md).
_pf_apgtis_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "IdentitySource", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigw-token-authorizer-identity-source", "ERROR", name,
	"Properties.IdentitySource",
	"TOKEN authorizer has no IdentitySource; the authorizer create fails with \"IdentitySource cannot be empty\"",
	"Set IdentitySource, e.g. method.request.header.Authorization",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGateway::Authorizer")
	resolve(name, "Properties.Type") == "TOKEN"
	_pf_apgtis_missing(name)
}
