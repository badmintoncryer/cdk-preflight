package cdk_preflight

import rego.v1

# Deploying an API with zero methods fails. Judged only when the whole
# picture is in this template: the api is a sibling resource and it has no
# OpenAPI body (which would define methods invisibly). Absence is proven
# against the preprocessed document (see AGENTS.md).
_pf_apgdnm_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

_pf_apgdnm_served(api) if {
	some m in resources_of_type("AWS::ApiGateway::Method")
	resolve(m, "Properties.RestApiId") == api
}

violation contains make_diag_full("pf-apigw-deployment-no-methods", "ERROR", name,
	"Properties.RestApiId",
	sprintf("REST API '%s' has no AWS::ApiGateway::Method in this template; the deployment fails with \"The REST API doesn't contain any methods\"", [api]),
	"Add at least one AWS::ApiGateway::Method to the API before deploying it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-deployment.html") if {
	some name in resources_of_type("AWS::ApiGateway::Deployment")
	api := resolve(name, "Properties.RestApiId")
	api in resources_of_type("AWS::ApiGateway::RestApi")
	_pf_apgdnm_absent(api, "Body")
	_pf_apgdnm_absent(api, "BodyS3Location")
	not _pf_apgdnm_served(api)
}
