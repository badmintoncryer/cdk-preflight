package cdk_preflight

import rego.v1

# Both authorizer-backed authorization types point at an Authorizer; the
# method create rejects them without one. Absence is proven against the
# preprocessed document (see AGENTS.md).
_pf_apgmaid_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "AuthorizerId", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigw-method-authorizer-id", "ERROR", name,
	"Properties.AuthorizerId",
	sprintf("AuthorizationType '%s' is set but AuthorizerId is not; the method create fails with \"Invalid authorizer ID specified. Setting the authorization type to CUSTOM or COGNITO_USER_POOLS requires a valid authorizer.\"", [at]),
	"Set AuthorizerId to the authorizer this method should use, or change AuthorizationType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-method.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	at := resolve(name, "Properties.AuthorizationType")
	at in {"CUSTOM", "COGNITO_USER_POOLS"}
	_pf_apgmaid_missing(name)
}
