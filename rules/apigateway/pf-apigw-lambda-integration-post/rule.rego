package cdk_preflight

import rego.v1

# API Gateway calls a Lambda function through the Lambda Invoke API, which only
# answers POST. PutIntegration accepts any IntegrationHttpMethod, so a GET
# integration deploys and then every request returns 500. Only integrations
# whose Uri is visibly a Lambda invocation path are judged; the Uri is usually
# an Fn::Sub or Fn::Join, which the engine keeps as a __dynamic string.
_pf_aplip_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html#cfn-apigateway-method-integration-integrationhttpmethod"

_pf_aplip_text(v) := v if is_string(v)

_pf_aplip_text(v) := t if {
	is_object(v)
	t := object.get(v, "__dynamic", null)
	is_string(t)
}

violation contains make_diag_full("pf-apigw-lambda-integration-post", "ERROR", name,
	"Properties.Integration.IntegrationHttpMethod",
	sprintf("A Lambda integration is called with IntegrationHttpMethod '%s'; the Lambda Invoke API only takes POST, so every request to this method returns 500 (the Lambda endpoint answers AccessDeniedException)", [m]),
	"Set Integration.IntegrationHttpMethod to POST (the method's own HttpMethod can stay as it is)",
	_pf_aplip_url) if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	props := input.resources[name].properties
	is_object(props)
	integ := object.get(props, "Integration", null)
	is_object(integ)
	object.get(integ, "Type", null) in {"AWS", "AWS_PROXY"}
	m := object.get(integ, "IntegrationHttpMethod", null)
	is_string(m)
	upper(m) != "POST"
	contains(_pf_aplip_text(object.get(integ, "Uri", null)), ":lambda:path/2015-03-31/functions/")
}
