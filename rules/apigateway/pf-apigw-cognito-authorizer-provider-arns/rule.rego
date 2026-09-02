package cdk_preflight

import rego.v1

# A Cognito authorizer validates tokens against the user pools listed in
# ProviderARNs; the create call rejects its absence. Absence is proven
# against the preprocessed document (see AGENTS.md).
_pf_apgcpa_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "ProviderARNs", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigw-cognito-authorizer-provider-arns", "ERROR", name,
	"Properties.ProviderARNs",
	"COGNITO_USER_POOLS authorizer has no ProviderARNs; the authorizer create fails with \"ProviderARNs cannot be empty\"",
	"Set ProviderARNs to the Cognito user pool ARN(s) this authorizer should use",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-authorizer.html") if {
	some name in resources_of_type("AWS::ApiGateway::Authorizer")
	resolve(name, "Properties.Type") == "COGNITO_USER_POOLS"
	_pf_apgcpa_missing(name)
}
