package cdk_preflight

import rego.v1

# Mirrors cfn-lint E3660 for REST APIs, which has no ApiGatewayV2
# counterpart: without a Body to carry info.title, Name is mandatory.
# Absence is proven against the preprocessed document (see AGENTS.md).
_pf_agv2anr_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-api-name-required", "ERROR", name,
	"Properties.Name",
	"Api has no Name and no OpenAPI body to take one from; the API create fails with \"Invalid API name specified\"",
	"Set Name, or provide the definition via Body / BodyS3Location",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Api")
	_pf_agv2anr_absent(name, "Name")
	_pf_agv2anr_absent(name, "Body")
	_pf_agv2anr_absent(name, "BodyS3Location")
}
