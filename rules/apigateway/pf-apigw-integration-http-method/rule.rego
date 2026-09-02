package cdk_preflight

import rego.v1

# Every integration type except MOCK calls a backend and needs the HTTP
# method to call it with. Verified for all four non-MOCK types. Absence is
# proven against the preprocessed document (see AGENTS.md).
_pf_apgihm_types := {"AWS", "AWS_PROXY", "HTTP", "HTTP_PROXY"}

_pf_apgihm_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	integ := object.get(props, "Integration", {})
	is_object(integ)
	object.get(integ, "IntegrationHttpMethod", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigw-integration-http-method", "ERROR", name,
	"Properties.Integration.IntegrationHttpMethod",
	sprintf("Integration type '%s' has no IntegrationHttpMethod; the method create fails with \"Enumeration value for HttpMethod must be non-empty\"", [t]),
	"Set Integration.IntegrationHttpMethod (POST for AWS/AWS_PROXY Lambda backends)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-method.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	t := resolve(name, "Properties.Integration.Type")
	t in _pf_apgihm_types
	_pf_apgihm_missing(name)
}
